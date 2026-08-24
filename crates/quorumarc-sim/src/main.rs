use std::process::ExitCode;

use quorumarc_sim::explore;

fn main() -> ExitCode {
    let mut depth = 8_usize;
    let mut require_safe = false;
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--depth" => {
                let Some(value) = arguments.next() else {
                    eprintln!("missing value after --depth");
                    return ExitCode::from(2);
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    eprintln!("invalid --depth value: {value}");
                    return ExitCode::from(2);
                };
                depth = parsed;
            }
            "--require-safe" => require_safe = true,
            "--help" | "-h" => {
                println!("Usage: quorumarc-sim [--depth N] [--require-safe]");
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("unknown argument: {unknown}");
                return ExitCode::from(2);
            }
        }
    }

    let report = explore(depth);
    println!("QuorumArc Gate 0 deterministic model");
    println!("depth: {}", report.depth);
    println!("unique states: {}", report.states_explored);
    println!("applied transitions: {}", report.transitions_explored);
    println!("rejected promotions: {}", report.rejected_promotions);
    println!("single-writer violations: {}", report.violations.len());

    if require_safe && !report.is_safe() {
        if let Some(first) = report.violations.first() {
            let trace = first
                .trace
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" -> ");
            eprintln!("first violating trace: {trace}");
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
