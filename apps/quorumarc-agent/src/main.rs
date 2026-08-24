use std::process::ExitCode;

fn main() -> ExitCode {
    let report = quorumarc_agent::execute(std::env::args_os().skip(1));
    for line in report.stdout() {
        println!("{line}");
    }
    for line in report.stderr() {
        eprintln!("{line}");
    }
    ExitCode::from(report.exit_code())
}
