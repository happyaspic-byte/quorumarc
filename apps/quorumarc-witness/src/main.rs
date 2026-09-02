use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = match utf8_arguments(std::env::args_os().skip(1)) {
        Ok(arguments) => arguments,
        Err(()) => {
            let result = writeln!(
                io::stderr().lock(),
                "reason=CLI_USAGE_ERROR detail=argument-is-not-valid-UTF-8"
            );
            return if result.is_ok() {
                ExitCode::from(2)
            } else {
                ExitCode::from(74)
            };
        }
    };
    let code = quorumarc_witness::execute(arguments, &mut io::stdout(), &mut io::stderr());
    ExitCode::from(code)
}

fn utf8_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Vec<String>, ()> {
    arguments
        .into_iter()
        .map(|argument| argument.into_string().map_err(|_| ()))
        .collect()
}
