use std::{env, process::ExitCode};

use byo_core::{PRODUCT_NAME, PROJECT_STATUS};

fn print_help() {
    println!(
        "{PRODUCT_NAME}\n\
         Project status: {PROJECT_STATUS}\n\n\
         Usage: byo [OPTIONS]\n\n\
         Options:\n\
           -h, --help       Print help\n\
           -V, --version    Print version\n\n\
         Inspection commands are intentionally not implemented in this foundation."
    );
}
fn main() -> ExitCode {
    match env::args_os().nth(1) {
        None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(argument) if argument == "-h" || argument == "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(argument) if argument == "-V" || argument == "--version" => {
            println!("byo {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(_) => {
            eprintln!(
                "error: inspection commands are not implemented in the {PROJECT_STATUS} foundation"
            );
            eprintln!("Run 'byo --help' for available options.");
            ExitCode::from(2)
        }
    }
}
