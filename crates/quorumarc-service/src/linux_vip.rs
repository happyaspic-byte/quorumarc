use std::net::IpAddr;

use futures::TryStreamExt;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage, AddressProtocol};

use crate::adapters::{AdapterError, CloseReason, EffectAdapter, VipState};

pub const QUORUMARC_ADDR_PROTOCOL: u8 = 188;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectOpenAuthorization {
    workload_id: String,
    node_id: String,
    epoch: u64,
    receipt_digest: [u8; 32],
}

impl EffectOpenAuthorization {
    pub fn new(
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        epoch: u64,
        receipt_digest: [u8; 32],
    ) -> Result<Self, AdapterError> {
        let workload_id = workload_id.into();
        let node_id = node_id.into();
        if workload_id.is_empty()
            || node_id.is_empty()
            || epoch == 0
            || receipt_digest.iter().all(|byte| *byte == 0)
        {
            return Err(AdapterError::ReceiptRequired);
        }
        Ok(Self {
            workload_id,
            node_id,
            epoch,
            receipt_digest,
        })
    }

    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VipOwnership {
    Owned,
    Foreign,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VipObservation {
    pub interface: String,
    pub address: IpAddr,
    pub prefix_len: u8,
    pub ownership: VipOwnership,
}

impl VipObservation {
    #[must_use]
    pub fn owned(interface: impl Into<String>, address: IpAddr, prefix_len: u8) -> Self {
        Self {
            interface: interface.into(),
            address,
            prefix_len,
            ownership: VipOwnership::Owned,
        }
    }

    #[must_use]
    pub fn foreign(interface: impl Into<String>, address: IpAddr, prefix_len: u8) -> Self {
        Self {
            interface: interface.into(),
            address,
            prefix_len,
            ownership: VipOwnership::Foreign,
        }
    }

    #[must_use]
    pub fn is_owned(&self) -> bool {
        matches!(self.ownership, VipOwnership::Owned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VipBackendError {
    PermissionDenied,
    InterfaceNotFound,
    AddressConflict,
    ReadBackFailed,
    Io,
}

pub trait VipBackend {
    fn observe(
        &mut self,
        interface: &str,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<Option<VipObservation>, VipBackendError>;

    fn add(&mut self, observation: &VipObservation) -> Result<(), VipBackendError>;

    fn delete(&mut self, observation: &VipObservation) -> Result<(), VipBackendError>;
}

pub struct NetlinkVipBackend {
    runtime: tokio::runtime::Runtime,
    handle: rtnetlink::Handle,
}

impl std::fmt::Debug for NetlinkVipBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NetlinkVipBackend")
    }
}

impl NetlinkVipBackend {
    pub fn connect() -> Result<Self, VipBackendError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|_error| VipBackendError::Io)?;
        let (connection, handle, _) = rtnetlink::new_connection().map_err(map_io_error)?;
        runtime.spawn(connection);
        Ok(Self { runtime, handle })
    }

    async fn link_index(&self, interface: &str) -> Result<u32, VipBackendError> {
        let mut links = self.handle.link().get().match_name(interface).execute();
        let link = links
            .try_next()
            .await
            .map_err(map_netlink_error)?
            .ok_or(VipBackendError::InterfaceNotFound)?;
        if links.try_next().await.map_err(map_netlink_error)?.is_some() {
            return Err(VipBackendError::ReadBackFailed);
        }
        Ok(link.header.index)
    }

    async fn find_address(
        &self,
        interface: &str,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<Option<(AddressMessage, VipObservation)>, VipBackendError> {
        let index = self.link_index(interface).await?;
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_prefix_length_filter(prefix_len)
            .set_address_filter(address)
            .execute();
        let mut matched = None;
        while let Some(message) = addresses.try_next().await.map_err(map_netlink_error)? {
            let owned = message.attributes.iter().any(|attribute| {
                matches!(
                    attribute,
                    AddressAttribute::Protocol(AddressProtocol::Other(protocol))
                        if *protocol == QUORUMARC_ADDR_PROTOCOL
                )
            });
            if matched.is_some() {
                return Err(VipBackendError::ReadBackFailed);
            }
            matched = Some((
                message,
                if owned {
                    VipObservation::owned(interface, address, prefix_len)
                } else {
                    VipObservation::foreign(interface, address, prefix_len)
                },
            ));
        }
        Ok(matched)
    }
}

impl VipBackend for NetlinkVipBackend {
    fn observe(
        &mut self,
        interface: &str,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<Option<VipObservation>, VipBackendError> {
        self.runtime
            .block_on(self.find_address(interface, address, prefix_len))
            .map(|result| result.map(|(_, observation)| observation))
    }

    fn add(&mut self, observation: &VipObservation) -> Result<(), VipBackendError> {
        if !observation.is_owned() {
            return Err(VipBackendError::AddressConflict);
        }
        let interface = observation.interface.clone();
        let address = observation.address;
        let prefix_len = observation.prefix_len;
        let handle = self.handle.clone();
        self.runtime.block_on(async move {
            let mut links = handle.link().get().match_name(interface).execute();
            let link = links
                .try_next()
                .await
                .map_err(map_netlink_error)?
                .ok_or(VipBackendError::InterfaceNotFound)?;
            let mut request = handle.address().add(link.header.index, address, prefix_len);
            request
                .message_mut()
                .attributes
                .push(AddressAttribute::Protocol(AddressProtocol::Other(
                    QUORUMARC_ADDR_PROTOCOL,
                )));
            request.execute().await.map_err(map_netlink_error)
        })
    }

    fn delete(&mut self, observation: &VipObservation) -> Result<(), VipBackendError> {
        if !observation.is_owned() {
            return Err(VipBackendError::AddressConflict);
        }
        let interface = observation.interface.clone();
        let address = observation.address;
        let prefix_len = observation.prefix_len;
        let handle = self.handle.clone();
        self.runtime.block_on(async move {
            let backend = NetlinkLookup { handle: &handle };
            let Some(message) = backend.find_owned(&interface, address, prefix_len).await? else {
                return Ok(());
            };
            handle
                .address()
                .del(message)
                .execute()
                .await
                .map_err(map_netlink_error)
        })
    }
}

struct NetlinkLookup<'a> {
    handle: &'a rtnetlink::Handle,
}

impl NetlinkLookup<'_> {
    async fn find_owned(
        &self,
        interface: &str,
        address: IpAddr,
        prefix_len: u8,
    ) -> Result<Option<AddressMessage>, VipBackendError> {
        let mut links = self.handle.link().get().match_name(interface).execute();
        let index = links
            .try_next()
            .await
            .map_err(map_netlink_error)?
            .ok_or(VipBackendError::InterfaceNotFound)?
            .header
            .index;
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_prefix_length_filter(prefix_len)
            .set_address_filter(address)
            .execute();
        while let Some(message) = addresses.try_next().await.map_err(map_netlink_error)? {
            if message.attributes.iter().any(|attribute| {
                matches!(
                    attribute,
                    AddressAttribute::Protocol(AddressProtocol::Other(protocol))
                        if *protocol == QUORUMARC_ADDR_PROTOCOL
                )
            }) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }
}

fn map_io_error(error: std::io::Error) -> VipBackendError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => VipBackendError::PermissionDenied,
        std::io::ErrorKind::NotFound => VipBackendError::InterfaceNotFound,
        std::io::ErrorKind::AlreadyExists => VipBackendError::AddressConflict,
        _ => VipBackendError::Io,
    }
}

fn map_netlink_error(error: rtnetlink::Error) -> VipBackendError {
    let detail = error.to_string();
    if detail.contains("Operation not permitted") || detail.contains("Permission denied") {
        VipBackendError::PermissionDenied
    } else if detail.contains("No such device") {
        VipBackendError::InterfaceNotFound
    } else if detail.contains("File exists") {
        VipBackendError::AddressConflict
    } else {
        VipBackendError::Io
    }
}

#[derive(Debug)]
pub struct LinuxVipEffectAdapter<B> {
    workload_id: String,
    node_id: String,
    interface: String,
    address: IpAddr,
    prefix_len: u8,
    state: VipState,
    last_epoch: u64,
    backend: B,
}

impl<B: VipBackend> LinuxVipEffectAdapter<B> {
    pub fn new(
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        vip_cidr: &str,
        interface: impl Into<String>,
        backend: B,
    ) -> Result<Self, AdapterError> {
        let (address, prefix_len) = parse_cidr(vip_cidr)?;
        let interface = interface.into();
        if interface.is_empty() || interface.len() > 15 {
            return Err(AdapterError::WrongTarget);
        }
        Ok(Self {
            workload_id: workload_id.into(),
            node_id: node_id.into(),
            interface,
            address,
            prefix_len,
            state: VipState::Detached,
            last_epoch: 0,
            backend,
        })
    }

    #[must_use]
    pub const fn state(&self) -> VipState {
        self.state
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn verify_attached(&mut self) -> Result<(), AdapterError> {
        match self.state {
            VipState::Attached(_) => {
                match self
                    .backend
                    .observe(&self.interface, self.address, self.prefix_len)
                {
                    Ok(Some(observation)) if observation.is_owned() => Ok(()),
                    _ => {
                        self.state = VipState::Detached;
                        Err(AdapterError::EffectNotClosed)
                    }
                }
            }
            VipState::Detached => Err(AdapterError::EffectNotClosed),
        }
    }

    pub fn attach(&mut self, authorization: &EffectOpenAuthorization) -> Result<(), AdapterError> {
        if authorization.workload_id() != self.workload_id
            || authorization.node_id() != self.node_id
        {
            return Err(AdapterError::WrongTarget);
        }
        if authorization.epoch() == 0 {
            return Err(AdapterError::ReceiptRequired);
        }
        if authorization.epoch() < self.last_epoch {
            return Err(AdapterError::StaleEpoch);
        }
        if let VipState::Attached(epoch) = self.state {
            if epoch == authorization.epoch() {
                self.verify_attached()?;
                return Ok(());
            }
            return Err(AdapterError::EffectNotClosed);
        }
        let pre_existing = self
            .backend
            .observe(&self.interface, self.address, self.prefix_len)
            .map_err(|_error| AdapterError::EffectNotClosed)?;
        if let Some(existing) = pre_existing {
            if existing.is_owned() {
                self.state = VipState::Attached(authorization.epoch());
                self.last_epoch = authorization.epoch();
                return Ok(());
            }
            return Err(AdapterError::ReadBackMismatch);
        }
        let target = VipObservation::owned(&self.interface, self.address, self.prefix_len);
        if self.backend.add(&target).is_err() {
            self.state = VipState::Detached;
            return Err(AdapterError::EffectNotClosed);
        }
        self.state = VipState::Attached(authorization.epoch());
        match self
            .backend
            .observe(&self.interface, self.address, self.prefix_len)
        {
            Ok(Some(observation)) if observation.is_owned() => {
                self.last_epoch = authorization.epoch();
                Ok(())
            }
            _ => {
                if self.backend.delete(&target).is_ok()
                    && matches!(
                        self.backend
                            .observe(&self.interface, self.address, self.prefix_len),
                        Ok(None)
                    )
                {
                    self.state = VipState::Detached;
                }
                Err(AdapterError::EffectNotClosed)
            }
        }
    }

    pub fn detach(&mut self, _reason: CloseReason) -> Result<(), AdapterError> {
        let target = VipObservation::owned(&self.interface, self.address, self.prefix_len);
        let observation = self
            .backend
            .observe(&self.interface, self.address, self.prefix_len)
            .map_err(|_error| AdapterError::EffectNotClosed)?;
        if let Some(existing) = observation {
            if existing.is_owned() {
                self.backend
                    .delete(&target)
                    .map_err(|_error| AdapterError::EffectNotClosed)?;
                match self
                    .backend
                    .observe(&self.interface, self.address, self.prefix_len)
                {
                    Ok(None) => {}
                    _ => return Err(AdapterError::EffectNotClosed),
                }
            } else {
                return Err(AdapterError::ReadBackMismatch);
            }
        }
        self.state = VipState::Detached;
        Ok(())
    }
}

impl<B: VipBackend> EffectAdapter for LinuxVipEffectAdapter<B> {
    fn verify_closed(&self) -> Result<(), AdapterError> {
        match self.state {
            VipState::Detached => Ok(()),
            VipState::Attached(_) => Err(AdapterError::EffectNotClosed),
        }
    }

    fn open(&mut self, _workload: &str, _epoch: u64) -> Result<(), AdapterError> {
        Err(AdapterError::ReceiptRequired)
    }

    fn open_with_receipt(
        &mut self,
        workload: &str,
        epoch: u64,
        receipt_digest: [u8; 32],
    ) -> Result<(), AdapterError> {
        let authorization =
            EffectOpenAuthorization::new(workload, &self.node_id, epoch, receipt_digest)?;
        self.attach(&authorization)
    }

    fn close(&mut self, reason: CloseReason) -> Result<(), AdapterError> {
        self.detach(reason)
    }
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), AdapterError> {
    let Some((address, prefix)) = value.rsplit_once('/') else {
        return Err(AdapterError::WrongTarget);
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return Err(AdapterError::WrongTarget);
    };
    let Ok(prefix_len) = prefix.parse::<u8>() else {
        return Err(AdapterError::WrongTarget);
    };
    match address {
        IpAddr::V4(_) if prefix_len <= 32 => Ok((address, prefix_len)),
        IpAddr::V6(_) if prefix_len <= 128 => Ok((address, prefix_len)),
        _ => Err(AdapterError::WrongTarget),
    }
}
