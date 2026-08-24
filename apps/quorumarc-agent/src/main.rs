use std::process::ExitCode;

const NOT_IMPLEMENTED: u8 = 78;

fn main() -> ExitCode {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("status"));

    match command.as_str() {
        "status" => {
            println!("quorumarc-agent gate=0 mode=research effect_gate=closed");
            println!("automatic promotion is intentionally disabled");
            ExitCode::SUCCESS
        }
        "promote" | "activate" => {
            eprintln!(
                "refused: Gate 0 has no durable consensus, signed proof, or real fence adapter"
            );
            ExitCode::from(NOT_IMPLEMENTED)
        }
        "--help" | "-h" => {
            println!("Usage: quorumarc-agent [status|promote]");
            println!("Gate 0 always refuses promotion and activation.");
            ExitCode::SUCCESS
        }
        unknown => {
            eprintln!("unknown command: {unknown}");
            ExitCode::from(2)
        }
    }
}
