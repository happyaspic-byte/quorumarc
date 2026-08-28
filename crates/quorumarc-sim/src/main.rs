use std::process::ExitCode;

use quorumarc_sim::{explore, run_seeded_scenarios};

fn main() -> ExitCode {
    let mut depth = 8_usize;
    let mut scenarios = None::<u64>;
    let mut seed = 0x5eed_u64;
    let mut max_steps = 32_usize;
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
            "--scenarios" => {
                let Some(value) = arguments.next() else {
                    eprintln!("missing value after --scenarios");
                    return ExitCode::from(2);
                };
                let Ok(parsed) = value.parse::<u64>() else {
                    eprintln!("invalid --scenarios value: {value}");
                    return ExitCode::from(2);
                };
                scenarios = Some(parsed);
            }
            "--seed" => {
                let Some(value) = arguments.next() else {
                    eprintln!("missing value after --seed");
                    return ExitCode::from(2);
                };
                let Ok(parsed) = value.parse::<u64>() else {
                    eprintln!("invalid --seed value: {value}");
                    return ExitCode::from(2);
                };
                seed = parsed;
            }
            "--steps" => {
                let Some(value) = arguments.next() else {
                    eprintln!("missing value after --steps");
                    return ExitCode::from(2);
                };
                let Ok(parsed) = value.parse::<usize>() else {
                    eprintln!("invalid --steps value: {value}");
                    return ExitCode::from(2);
                };
                max_steps = parsed;
            }
            "--require-safe" => require_safe = true,
            "--help" | "-h" => {
                println!(
                    "Usage: quorumarc-sim [--depth N | --scenarios N [--seed S] [--steps M]] [--require-safe]"
                );
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("unknown argument: {unknown}");
                return ExitCode::from(2);
            }
        }
    }

    if let Some(count) = scenarios {
        let report = run_seeded_scenarios(seed, count, max_steps);
        println!("QuorumArc Gate 0 seeded Monte Carlo simulator");
        println!("seed: 0x{:016x}", report.seed);
        println!("scenarios: {}", report.scenarios);
        println!("max steps: {}", report.max_steps);
        println!("applied steps: {}", report.steps_executed);
        println!("reordered events: {}", report.reordered_events);
        println!("rejected promotions: {}", report.rejected_promotions);
        println!("schedule digest: 0x{:016x}", report.schedule_digest);
        println!(
            "single-writer violations: {}",
            if report.first_violation.is_some() {
                1
            } else {
                0
            }
        );

        if let Some(violation) = report.first_violation {
            let trace = violation
                .trace
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" -> ");
            eprintln!("first violating trace: {trace}");
            if require_safe {
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
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
