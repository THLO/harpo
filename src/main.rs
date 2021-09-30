extern crate clap;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use harpo::seed_phrase::SeedPhrase;
use harpo::{create_secret_shared_seed_phrases, reconstruct_seed_phrase};
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
        .about("Creates secret-shared seed phrases")
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
        .about("Reconstructs a seed phrase")
        .arg(file_argument)
        .arg(interactive_argument)
        .group(input_group);

    // The application including the top-level arguments.
    App::new("harpo")
        .version(VERSION)
        .author(AUTHORS)
        .about("A tool to create secret-shared seed phrases and reconstruct seed phrases.")
        .arg(
            Arg::with_name("verbose") // Verbose output can be enabled.
                .short("v")
                .long("verbose")
                .help("Prints verbose output")
                .takes_value(false),
        )
        // Commented out until an implementation is added.
        //.arg(
        //    Arg::with_name("word-list") // A word-list file can be provided.
        //        .short("w")
        //        .long("word-list")
        //        .help("Reads the word list from the provided file")
        //        .takes_value(true),
        //)
        .subcommand(create_subcommand)
        .subcommand(reconstruct_subcommand)
        .get_matches()
}

fn read_seed_phrase_from_file(file_path: &str) -> Result<SeedPhrase, Box<dyn Error>> {
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
            Ok(SeedPhrase::new(&mnemonic_words))
        }
        None => Err(format!(
            "Error. Could not read the seed phrase from the file {}.",
            file_path
        )
        .into()),
    }
}

fn read_seed_phrase_interactively() -> Result<SeedPhrase, Box<dyn Error>> {
    Err("Not implemented yet!".into())
}

fn handle_create(command_line: &clap::ArgMatches) -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
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
    let seed_phrase = if let Some(file_path) = command_line.value_of("file") {
        read_seed_phrase_from_file(file_path)?
    } else {
        // The seed phrase must be entered interactively.
        read_seed_phrase_interactively()?
    };
    // Get the --no-embedding flag.
    let embed_indices = !command_line.is_present("no-embedding");
    // Create the shares and return them.
    create_secret_shared_seed_phrases(&seed_phrase, threshold, num_shares, embed_indices)
}

fn convert_line_to_seed_phrase(line: &str) -> Option<SeedPhrase> {
    let mut words: Vec<String> = line.to_lowercase().split(' ').map(str::to_string).collect();
    if words.is_empty() {
        return None;
    }
    if words[0].contains(':') {
        let index_string = words.remove(0);
        match index_string.replace(":", "").parse::<u32>() {
            Ok(index) => Some(SeedPhrase::new_with_index(&words, index)),
            Err(_) => None,
        }
    } else {
        Some(SeedPhrase::new(&words))
    }
}

fn read_seed_phrases_from_file(file_path: &str) -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
    let file_content = read_to_string(file_path)?;
    let seed_phrase_options: Vec<Option<SeedPhrase>> = file_content
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| convert_line_to_seed_phrase(line))
        .collect();
    let original_length = seed_phrase_options.len();
    let seed_phrases: Vec<SeedPhrase> = seed_phrase_options.into_iter().flatten().collect();
    if original_length != seed_phrases.len() {
        Err("Encountered an invalid seed phrase in the file.".into())
    } else {
        Ok(seed_phrases)
    }
}

fn read_seed_phrases_interactively() -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
    Err("Not implemented yet!".into())
}

fn handle_reconstruct(command_line: &clap::ArgMatches) -> Result<SeedPhrase, Box<dyn Error>> {
    // Read the input.
    let seed_phrases = if let Some(file_path) = command_line.value_of("file") {
        read_seed_phrases_from_file(file_path)?
    } else {
        // The seed phrases must be entered interactively.
        read_seed_phrases_interactively()?
    };
    // Reconstruct the seed phrase.
    reconstruct_seed_phrase(&seed_phrases)
}

/// The main function uses the command-line arguments to trigger the right command execution.
fn main() {
    let command_line = parse_command_line();
    match command_line.subcommand_name() {
        Some(CREATE_SUBCOMMAND) => {
            match handle_create(
                &command_line
                    .subcommand_matches(CREATE_SUBCOMMAND)
                    .expect("The 'create' command must be specififed."),
            ) {
                Ok(seed_phrases) => {
                    for seed_phrase in seed_phrases {
                        println!("Error: {}", seed_phrase);
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
                Ok(seed_phrase) => println!("{}", seed_phrase),
                Err(err) => println!("Error: {}", err),
            };
        }
        _ => println!("Error: A subcommand must be provided. Use --help to view options."),
    };
}
