use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let report = quorumarc_agent::execute(std::env::args_os().skip(1));
    let stdout_result = write_lines(&mut io::stdout().lock(), report.stdout());
    let stderr_result = write_lines(&mut io::stderr().lock(), report.stderr());
    match stdout_result.and(stderr_result) {
        Ok(()) => ExitCode::from(report.exit_code()),
        Err(_error) => {
            let _diagnostic_result = writeln!(
                io::stderr().lock(),
                "{{\"event\":\"cli-output\",\"status\":\"refused\",\"reason_code\":\"CLI_OUTPUT_IO_ERROR\"}}"
            );
            ExitCode::from(74)
        }
    }
}

fn write_lines(writer: &mut impl Write, lines: &[String]) -> io::Result<()> {
    for line in lines {
        writeln!(writer, "{line}")?;
    }
    Ok(())
}
