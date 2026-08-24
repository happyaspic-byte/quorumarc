use std::process::ExitCode;

fn main() -> ExitCode {
    let code = quorumarc_witness::execute(
        std::env::args().skip(1),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(code)
}
