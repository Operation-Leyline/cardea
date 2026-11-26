//! Fill the directory for a pool that already has users
//! ([`cardea_cognito::backfill`]). An operator runs it with their own AWS
//! credentials; the region is the pool's.

use std::process::ExitCode;

use aws_config::{BehaviorVersion, retry::RetryConfig};
use cardea_cognito::{
    AwsDirectory,
    backfill::{Mode, backfill},
};

const USAGE: &str = "\
usage: cardea-backfill --pool <user pool id> --table <directory table> [--apply] [--activate]

  (neither flag)  dry run: report what is missing, write nothing
  --apply         write the missing rows
  --activate      with --apply: open the directory (SYSTEM#READY) once a second
                  pass finds every user covered

Prints counts and user ids (sub), never addresses.
Exit status: 0 done, 1 failed, 2 something is left to settle.";

/// How often a throttled or failed call is tried: a backfill makes many calls
/// in a row, and has no deadline.
const ATTEMPTS: u32 = 10;

#[derive(Debug, PartialEq)]
struct Arguments {
    pool: String,
    table: String,
    mode: Mode,
}

/// The arguments after the program's name; `None` asks for the usage text.
fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Option<Arguments>, String> {
    let mut arguments = arguments.into_iter();
    let (mut pool, mut table) = (None, None);
    let (mut apply, mut activate) = (false, false);
    while let Some(argument) = arguments.next() {
        let slot = match argument.as_str() {
            "--help" | "-h" => return Ok(None),
            "--apply" => {
                apply = true;
                continue;
            }
            "--activate" => {
                activate = true;
                continue;
            }
            "--pool" => &mut pool,
            "--table" => &mut table,
            // Not echoed: a mistyped argument may be anything.
            _ => return Err("unknown argument".into()),
        };
        *slot = Some(
            arguments
                .next()
                .filter(|value| !value.is_empty() && !value.starts_with("--"))
                .ok_or_else(|| format!("{argument} needs a value"))?,
        );
    }
    let mode = match (apply, activate) {
        (false, false) => Mode::DryRun,
        (true, false) => Mode::Apply,
        (true, true) => Mode::ApplyAndActivate,
        (false, true) => return Err("--activate requires --apply".into()),
    };
    Ok(Some(Arguments {
        pool: pool.ok_or("--pool is required")?,
        table: table.ok_or("--table is required")?,
        mode,
    }))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments = match parse(std::env::args().skip(1)) {
        Ok(Some(arguments)) => arguments,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .retry_config(RetryConfig::standard().with_max_attempts(ATTEMPTS))
        .load()
        .await;
    let directory = AwsDirectory::from_config(&config, arguments.table, arguments.pool);
    match backfill(&directory, arguments.mode).await {
        Ok(report) => {
            print!("{report}");
            if report.needs_attention() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        // The message only: an SDK error's chain may quote what was sent.
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given(line: &str) -> Result<Option<Arguments>, String> {
        parse(line.split_whitespace().map(str::to_owned))
    }

    #[test]
    fn a_run_is_dry_unless_asked_to_apply() {
        for (flags, mode) in [
            ("", Mode::DryRun),
            ("--apply", Mode::Apply),
            ("--activate --apply", Mode::ApplyAndActivate),
        ] {
            let parsed = given(&format!("--pool us-east-1_A --table identities {flags}"));
            assert_eq!(
                parsed,
                Ok(Some(Arguments {
                    pool: "us-east-1_A".into(),
                    table: "identities".into(),
                    mode,
                }))
            );
        }
    }

    #[test]
    fn incomplete_and_unknown_arguments_are_refused() {
        for line in [
            "",
            "--pool us-east-1_A",
            "--table identities",
            "--pool --table identities",
            "--pool us-east-1_A --table",
            "--pool us-east-1_A --table identities --activate",
            "--pool us-east-1_A --table identities --aply",
        ] {
            assert!(given(line).is_err(), "{line}");
        }
        assert_eq!(given("--help"), Ok(None));
    }
}
