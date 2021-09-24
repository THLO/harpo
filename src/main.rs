extern crate clap;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use harpo::{create_secret_shared_mnemonic_codes, reconstruct_mnemonic_code};
use std::error::Error;

/// The subcommand to create secret shares.
const CREATE_SUBCOMMAND: &str = "create";

/// The subcommand to reconstruct a shared secret.
const RECONSTRUCT_SUBCOMMAND: &str = "reconstruct";

/// The function parses the command-line arguments.
fn parse_command_line<'a>() -> ArgMatches<'a> {
    // Extract the version from the Cargo.toml file.
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

    // The arguments that the subcommands share are defined first.

    // The argument --file is used to specify input stored in a file.
    let file_argument = Arg::with_name("file")
        .takes_value(true)
        .short("f")
        .long("file")
        .help("Uses the data in the provided file as input");

    // The argument --interactive is used to specify input in the terminal.
    let interactive_argument = Arg::with_name("interactive")
        .short("i")
        .long("interactive")
        .help("Enters the input interactively");

    // The input must be provided in a file or in the terminal.
    let input_group = ArgGroup::with_name("file_interactive")
        .args(&["file", "interactive"])
        .required(true);

    // The create subcommand.
    let create_subcommand = SubCommand::with_name(CREATE_SUBCOMMAND)
        .about("Creates secret-shared mnemonic codes")
        .arg(file_argument.clone())
        .arg(interactive_argument.clone())
        .arg(
            Arg::with_name("no-embedding") // The embedding of share indices can be turned off.
                .short("N")
                .long("no-embedding")
                .help("Stores share identifiers separately")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("num-shares") // The total number of shares.
                .required(true)
                .takes_value(true)
                .short("n")
                .long("num-shares")
                .help("Sets the total number of shares to the given value"),
        )
        .arg(
            Arg::with_name("threshold") // The threshold for reconstruction.
                .required(true)
                .takes_value(true)
                .short("t")
                .long("threshold")
                .help("Sets the threshold to the given value"),
        )
        .group(input_group.clone());

    // The reconstruct subcommand.
    let reconstruct_subcommand = SubCommand::with_name(RECONSTRUCT_SUBCOMMAND)
        .about("Reconstructs a mnemonic code")
        .arg(file_argument)
        .arg(interactive_argument)
        .group(input_group);

    // The application including the top-level arguments.
    App::new("harpo")
        .version(VERSION)
        .author(AUTHORS)
        .about("A tool to create secret-shared mnemonic codes and reconstruct mnemonic codes.")
        .arg(
            Arg::with_name("verbose") // Verbose output can be enabled.
                .short("v")
                .long("verbose")
                .help("Prints verbose output")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("word-list") // A word-list file can be provided.
                .short("w")
                .long("word-list")
                .help("Reads the word list from the provided file")
                .takes_value(true),
        )
        .subcommand(create_subcommand)
        .subcommand(reconstruct_subcommand)
        .get_matches()
}

fn handle_create(command_line: &clap::ArgMatches) -> Result<(), Box<dyn Error>> {
    // The unwrap() is okay because --num_shares must be provided.
    let num_shares = command_line.value_of("rate").unwrap().parse::<u32>()?;
    // The unwrap() is okay because --threshold must be provided.
    let threshold = command_line.value_of("treshold").unwrap().parse::<u32>()?;
    Ok(())
}

fn handle_reconstruct(command_line: &clap::ArgMatches) -> Result<(), Box<dyn Error>> {
    Ok(())
}

/// The main function uses the command-line arguments to trigger the right command execution.
fn main() {
    let command_line = parse_command_line();
    match command_line.subcommand_name() {
        Some(CREATE_SUBCOMMAND) => {
            match handle_create(&command_line) {
                Ok(result) => println!("{:?}", result),
                Err(err) => println!("Error: {}", err),
            };
        }
        Some(RECONSTRUCT_SUBCOMMAND) => {
            match handle_reconstruct(&command_line) {
                Ok(result) => println!("{:?}", result),
                Err(err) => println!("Error: {}", err),
            };
        }
        _ => println!("Error: A subcommand must be provided. Use --help to view options."),
    };
}
