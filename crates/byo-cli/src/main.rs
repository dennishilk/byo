use std::ffi::OsString;
use std::path::PathBuf;
use std::{env, process::ExitCode};

use byo_cli::{inspect_file_path, inspect_qr_path, render_human, render_json, report_exit_code};
use byo_core::{inspect_url, PRODUCT_NAME, PROJECT_STATUS};

enum CliCommand {
    Help,
    Version,
    File { path: PathBuf, json: bool },
    Qr { path: PathBuf, json: bool },
    Url { input: String, json: bool },
}

fn print_help() {
    println!(
        r#"{PRODUCT_NAME}
Project status: {PROJECT_STATUS}

Usage:
  byo [--json] file <PATH>
  byo [--json] qr <PATH>
  byo [--json] url <URL>
  byo --help
  byo --version

Commands:
  file <PATH>      Inspect a regular file read-only and offline
  qr <PATH>        Decode QR codes from a PNG or JPEG locally and offline
  url <URL>        Parse and inspect a URL without network activity

Options:
      --json       Emit the structured PRE-ALPHA JSON report
  -h, --help       Print help
  -V, --version    Print version"#
    );
}

fn parse_args() -> Result<CliCommand, String> {
    let mut arguments = env::args_os().skip(1);
    let mut json = false;

    loop {
        let Some(argument) = arguments.next() else {
            return Ok(CliCommand::Help);
        };
        if argument == "--json" {
            json = true;
            continue;
        }
        if argument == "-h" || argument == "--help" {
            return Ok(CliCommand::Help);
        }
        if argument == "-V" || argument == "--version" {
            return Ok(CliCommand::Version);
        }
        if argument == "file" {
            let Some(path) = arguments.next() else {
                return Err("the file command requires one PATH".to_owned());
            };
            json = parse_trailing_json(arguments, json)?;
            return Ok(CliCommand::File {
                path: PathBuf::from(path),
                json,
            });
        }
        if argument == "url" {
            let Some(input) = arguments.next() else {
                return Err("the url command requires one URL".to_owned());
            };
            let input = input
                .into_string()
                .map_err(|_| "the URL argument must be valid Unicode".to_owned())?;
            json = parse_trailing_json(arguments, json)?;
            return Ok(CliCommand::Url { input, json });
        }
        if argument == "qr" {
            let Some(path) = arguments.next() else {
                return Err("the qr command requires one PATH".to_owned());
            };
            json = parse_trailing_json(arguments, json)?;
            return Ok(CliCommand::Qr {
                path: PathBuf::from(path),
                json,
            });
        }

        return Err(format!(
            "unknown command or option: {}",
            byo_core::escape_for_terminal(&argument.to_string_lossy())
        ));
    }
}

fn parse_trailing_json(
    arguments: impl Iterator<Item = OsString>,
    mut json: bool,
) -> Result<bool, String> {
    for argument in arguments {
        if argument == "--json" && !json {
            json = true;
        } else {
            return Err(format!(
                "unexpected extra argument: {}",
                byo_core::escape_for_terminal(&argument.to_string_lossy())
            ));
        }
    }
    Ok(json)
}

fn print_report(report: &byo_core::Report, json: bool) -> Result<(), String> {
    if json {
        let rendered = render_json(report)
            .map_err(|_| "the structured report could not be serialized".to_owned())?;
        println!("{rendered}");
    } else {
        print!("{}", render_human(report));
    }
    Ok(())
}

fn run() -> Result<u8, String> {
    match parse_args()? {
        CliCommand::Help => {
            print_help();
            Ok(0)
        }
        CliCommand::Version => {
            println!("byo {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        CliCommand::File { path, json } => {
            let report = inspect_file_path(&path);
            print_report(&report, json)?;
            Ok(report_exit_code(&report))
        }
        CliCommand::Url { input, json } => {
            let report = inspect_url(&input);
            print_report(&report, json)?;
            Ok(report_exit_code(&report))
        }
        CliCommand::Qr { path, json } => {
            let report = inspect_qr_path(&path);
            print_report(&report, json)?;
            Ok(report_exit_code(&report))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!("Run 'byo --help' for usage.");
            ExitCode::from(2)
        }
    }
}
