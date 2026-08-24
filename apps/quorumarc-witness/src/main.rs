use std::process::ExitCode;

const NOT_IMPLEMENTED: u8 = 78;

fn main() -> ExitCode {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("status"));

    match command.as_str() {
        "status" => {
            println!("quorumarc-witness gate=0 mode=research voting=disabled");
            ExitCode::SUCCESS
        }
        "vote" | "certify" => {
            eprintln!("refused: Gate 0 has no durable consensus log, identity, or signing key");
            ExitCode::from(NOT_IMPLEMENTED)
        }
        "--help" | "-h" => {
            println!("Usage: quorumarc-witness [status|vote]");
            println!("Gate 0 always refuses votes and certificates.");
            ExitCode::SUCCESS
        }
        unknown => {
            eprintln!("unknown command: {unknown}");
            ExitCode::from(2)
        }
    }
}
