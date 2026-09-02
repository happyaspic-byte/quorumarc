#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: package-gate1a-lab.sh RELEASE_DIR OUTPUT_DIR" >&2
  exit 64
fi

release_dir="$1"
output_dir="$2"
bundle_name="quorumarc-gate1a-lab-x86_64-ubuntu"
staging_dir="$(mktemp -d)"
bundle_dir="${staging_dir}/${bundle_name}"

cleanup() {
  rm -rf -- "${staging_dir}"
}
trap cleanup EXIT

mkdir -p \
  "${bundle_dir}/bin" \
  "${bundle_dir}/docs" \
  "${bundle_dir}/spec" \
  "${output_dir}"

for binary in \
  quorumarc-agent \
  quorumarc-witness \
  quorumarc-cluster \
  quorumarc-lab \
  quorumarc-sim; do
  test -x "${release_dir}/${binary}"
  install -m 0755 "${release_dir}/${binary}" "${bundle_dir}/bin/${binary}"
done

install -m 0644 LICENSE "${bundle_dir}/LICENSE"
install -m 0644 README.md "${bundle_dir}/README.md"
install -m 0644 SECURITY.md "${bundle_dir}/SECURITY.md"
install -m 0644 Cargo.lock "${bundle_dir}/Cargo.lock"
install -m 0644 rust-toolchain.toml "${bundle_dir}/rust-toolchain.toml"
install -m 0644 deny.toml "${bundle_dir}/deny.toml"
install -m 0644 docs/*.md docs/*.toml "${bundle_dir}/docs/"
install -m 0644 spec/*.md "${bundle_dir}/spec/"

(
  cd "${bundle_dir}"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
  sha256sum --check SHA256SUMS
)

tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  -C "${staging_dir}" -cf - "${bundle_name}" \
  | gzip -n > "${output_dir}/${bundle_name}.tar.gz"
sha256sum "${output_dir}/${bundle_name}.tar.gz" \
  > "${output_dir}/${bundle_name}.tar.gz.sha256"
