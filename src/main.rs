extern crate clap;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use harpo::mnemonic::MnemonicCode;
use harpo::{create_secret_shared_mnemonic_codes, reconstruct_mnemonic_code};
use std::error::Error;
use std::fs::read_to_string;
use std::io::{self, Read};

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

fn read_mnemonic_code_from_file(file_path: &str) -> Result<MnemonicCode, Box<dyn Error>> {
    let file_content = read_to_string(file_path)?;
    let mnemonic_string = file_content
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty());
    match mnemonic_string {
        Some(string) => {
            let mnemonic_words: Vec<String> = string
                .to_lowercase()
                .split(' ')
                .map(str::to_string)
                .collect();
            Ok(MnemonicCode::new(&mnemonic_words))
        }
        None => Err(format!(
            "Error. Could not read the mnemonic code from the file {}.",
            file_path
        )
        .into()),
    }
}

fn read_mnemonic_code_interactively() -> Result<MnemonicCode, Box<dyn Error>> {
    Err("Not implemented yet!".into())
}

fn handle_create(command_line: &clap::ArgMatches) -> Result<Vec<MnemonicCode>, Box<dyn Error>> {
    // The unwrap() is okay because --num-shares must be provided.
    let num_shares = command_line
        .value_of("num-shares")
        .unwrap()
        .parse::<usize>()?;
    // The unwrap() is okay because --threshold must be provided.
    let threshold = command_line
        .value_of("threshold")
        .unwrap()
        .parse::<usize>()?;
    // Read the input.
    let mnemonic_code = if let Some(file_path) = command_line.value_of("file") {
        read_mnemonic_code_from_file(file_path)?
    } else {
        // The mnemonic code must be entered interactively.
        read_mnemonic_code_interactively()?
    };
    // Create the shares and return them.
    create_secret_shared_mnemonic_codes(&mnemonic_code, threshold, num_shares)
}

fn convert_line_to_mnemonic_code(line: &str) -> Option<MnemonicCode> {
    let mut words: Vec<String> = line.to_lowercase().split(' ').map(str::to_string).collect();
    if words.is_empty() {
        return None;
    }
    if words[0].contains(':') {
        let index_string = words.remove(0);
        match index_string.replace(":", "").parse::<u32>() {
            Ok(index) => Some(MnemonicCode::new_with_index(&words, index)),
            Err(_) => None,
        }
    } else {
        Some(MnemonicCode::new(&words))
    }
}

fn read_mnemonic_codes_from_file(file_path: &str) -> Result<Vec<MnemonicCode>, Box<dyn Error>> {
    let file_content = read_to_string(file_path)?;
    let mnemonic_code_options: Vec<Option<MnemonicCode>> = file_content
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| convert_line_to_mnemonic_code(line))
        .collect();
    let original_length = mnemonic_code_options.len();
    let mnemonic_codes: Vec<MnemonicCode> = mnemonic_code_options.into_iter().flatten().collect();
    if original_length != mnemonic_codes.len() {
        Err("Encountered an invalid mnemonic code in the file.".into())
    } else {
        Ok(mnemonic_codes)
    }
}

fn read_mnemonic_codes_interactively() -> Result<Vec<MnemonicCode>, Box<dyn Error>> {
    Err("Not implemented yet!".into())
}

fn handle_reconstruct(command_line: &clap::ArgMatches) -> Result<MnemonicCode, Box<dyn Error>> {
    // Read the input.
    let mnemonic_codes = if let Some(file_path) = command_line.value_of("file") {
        read_mnemonic_codes_from_file(file_path)?
    } else {
        // The mnemonic codes must be entered interactively.
        read_mnemonic_codes_interactively()?
    };
    // Reconstruct the mnemonic code.
    reconstruct_mnemonic_code(&mnemonic_codes)
}

/// The main function uses the command-line arguments to trigger the right command execution.
fn main() {
    let command_line = parse_command_line();
    match command_line.subcommand_name() {
        Some(CREATE_SUBCOMMAND) => {
            match handle_create(
                &command_line
                    .subcommand_matches(CREATE_SUBCOMMAND)
                    .expect("Error: The 'create' command must be specififed."),
            ) {
                Ok(mnemonic_codes) => {
                    for mnemonic_code in mnemonic_codes {
                        println!("{}", mnemonic_code);
                    }
                }
                Err(err) => println!("Error: {}", err),
            };
        }
        Some(RECONSTRUCT_SUBCOMMAND) => {
            match handle_reconstruct(
                &command_line
                    .subcommand_matches(RECONSTRUCT_SUBCOMMAND)
                    .expect("Error: The 'create' command must be specififed."),
            ) {
                Ok(mnemonic_code) => println!("{}", mnemonic_code),
                Err(err) => println!("Error: {}", err),
            };
        }
        _ => println!("Error: A subcommand must be provided. Use --help to view options."),
    };
}
