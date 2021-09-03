extern crate clap;
use harpo::{create, reconstruct};
use clap::{Arg, App, ArgGroup, ArgMatches, SubCommand};


const CREATE_SUBCOMMAND : &str = "create";
const RECONSTRUCT_SUBCOMMAND : &str = "reconstruct";

/// The function parses the command-line arguments.
fn parse_command_line<'a>() -> ArgMatches<'a> {
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");

    let file_argument = Arg::with_name("file")
        .takes_value(true)
        .short("f")
        .long("file")
        .help("Uses the data in the provided file as input");

    let interactive_argument = Arg::with_name("interactive")
        .short("i")
        .long("interactive")
        .help("Enters the input interactively");

    let threshold_argument = Arg::with_name("threshold")
        .takes_value(true)
        .short("t")
        .long("threshold")
        .help("Sets the threshold to the given value");

    let create_subcommand = SubCommand::with_name(CREATE_SUBCOMMAND)
        .about("Creates secret-shared passphrases.")
        .arg(file_argument.clone())
        .arg(interactive_argument.clone())
        .arg(threshold_argument.clone())
        .arg(
            Arg::with_name("num-shares")
                .required(true)
                .takes_value(true)
                .short("n")
                .long("num-shares")
                .help("Sets the total number of shares to the given value"))
        .group(ArgGroup::with_name("file_interactive")
                .args(&vec!["file", "interactive"])
                .required(true));

    let reconstruct_subcommand = SubCommand::with_name(RECONSTRUCT_SUBCOMMAND)
        .about("Reconstructs a passphrase")
        .arg(file_argument.clone())
        .arg(interactive_argument.clone())
        .arg(threshold_argument.clone())
        .group(ArgGroup::with_name("file_interactive")
                .args(&vec!["file", "interactive"])
                .required(true));

    App::new("harpo")
        .version(VERSION)
        .author("Thomas Locher")
        .about("A tool to create secret-shared passphrases and reconstruct passphrases.")
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Prints verbose output")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("no-embedding")
                .short("N")
                .long("no-embedding")
                .help("Stores share identifiers separately")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("word-list")
                .short("w")
                .long("word-list")
                .help("Reads the word list from the provided file")
                .takes_value(true),
        )
        .subcommand(create_subcommand)
        .subcommand(reconstruct_subcommand)
        .get_matches()
}

/// The main function uses the command-line arguments to trigger the right command execution.
fn main() {
    let command_line = parse_command_line();
    match command_line.subcommand_name() {
        Some(RECONSTRUCT_SUBCOMMAND) => create(),
        Some(CREATE_SUBCOMMAND) => reconstruct(),
        _ => println!("Error: A subcommand must be provided. Use --help to view options.")
    };
}
