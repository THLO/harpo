extern crate clap;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use harpo::seed_phrase::{SeedPhrase, MIN_NUM_WORDS};
use harpo::{create_secret_shared_seed_phrases, reconstruct_seed_phrase};
use std::error::Error;
use std::fs::read_to_string;

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
        // Commented out until an implementation is added.
        //.arg(
        //    Arg::with_name("verbose") // Verbose output can be enabled.
        //        .short("v")
        //        .long("verbose")
        //        .help("Prints verbose output")
        //        .takes_value(false),
        //)
        // Commented out until an implementation is added.
        //.arg(
        //    Arg::with_name("word-list") // A word-list file can be provided.
        //        .short("w")
        //        .long("word-list")
        //        .help("Reads the word list from the provided file")
        //        .takes_value(true),
        //)
        .subcommand(create_subcommand) // Add the create subcommand.
        .subcommand(reconstruct_subcommand) // Add the reconstruct subcommand.
        .get_matches()
}

/// The function converts the given string into a seed phrase.
///
/// The function takes a space-delimited seed phrase in the form of a string (slice) as its
/// argument and returns a [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) if the string can
/// be split into sufficiently many words.
/// Note that the function does not verify the validity of the provided words.
///
/// * `input` - The input seed phrase as a space-delimited string.
fn convert_string_to_seed_phrase(input: &str) -> Option<SeedPhrase> {
    // Break the input into words.
    let mut words: Vec<String> = input
        .replace(':', ": ") // If there is an index, ensure that it is a separate word.
        .to_lowercase() // No upper-case words are allowed.
        .trim() // Remove white spaces in the beginning and at the end.
        .split(' ') // Split the string.
        .filter(|word| !word.is_empty()) // Keep only words with a positive length.
        .map(str::to_string) // Map the string slices to strings.
        .collect(); // Collect the vector.
    if words.len() < MIN_NUM_WORDS {
        // Make sure that there are sufficiently many words.
        return None;
    }
    // If there is an explicit index, extract it from the list of words.
    if words[0].contains(':') {
        let index_string = words.remove(0);
        match index_string.replace(":", "").parse::<u32>() {
            Ok(index) => Some(SeedPhrase::new_with_index(&words, index)),
            Err(_) => None,
        }
    } else {
        // Otherwise, create a seed phrase without an index.
        Some(SeedPhrase::new(&words))
    }
}

/// The function reads a seed phrase from the given file.
///
/// The function takes a file path argument and reads in a
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) if possible.
///
/// * `file_path` - The path to the file containing the seed phrase.
fn read_seed_phrase_from_file(file_path: &str) -> Result<SeedPhrase, Box<dyn Error>> {
    // Read the file content.
    let file_content = read_to_string(file_path)?;
    // Find a line that might encode a seed phrase.
    let seed_phrase_string = file_content
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty());
    // If a seed phrase is found, turn the string into a SeedPhrase struct and return it.
    match seed_phrase_string {
        Some(seed_phrase_string) => match convert_string_to_seed_phrase(seed_phrase_string) {
            Some(seed_phrase) => Ok(seed_phrase),
            None => Err("Could not convert the input into a seed phrase.".into()),
        },
        None => Err(format!(
            "Could not read the seed phrase from the file {}.",
            file_path
        )
        .into()),
    }
}

/// The function reads a seed phrase from standard input.
///
/// The function reads a line from standard input and returns it as a
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) if possible.
fn read_seed_phrase_interactively() -> Result<SeedPhrase, Box<dyn Error>> {
    let mut seed_phrase_string = String::new();
    println!("Please enter your seed phrase (12, 15, 18, 21, or 24 space-delimited words):");
    // Read from standard input.
    let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    // If the input can be converted to a seed phrase, return the seed phrase.
    match convert_string_to_seed_phrase(&seed_phrase_string) {
        Some(seed_phrase) => Ok(seed_phrase),
        None => Err("Could not parse the seed phrase.".into()),
    }
}

/// The function handles the creation of secret-shared seed phrases.
///
/// The input to the function is the command-line arguments. If processing succeeds,
/// the function returns a vector of [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) structs.
///
/// * `command_line` - The command-line arguments.
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
    // Read the input fropm a file or interactively.
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

/// The function reads multiple seed phrases from a file.
///
/// The function takes a file path argument and reads in all seed phrases.
/// If processing succeeds, a vector of
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) is returned.
///
/// * `file_path` - The path to the file containing the seed phrases.
fn read_seed_phrases_from_file(file_path: &str) -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
    // Read the file content.
    let file_content = read_to_string(file_path)?;
    // Get all potential seed phrases.
    let seed_phrase_options: Vec<Option<SeedPhrase>> = file_content
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| convert_string_to_seed_phrase(line))
        .collect();
    // If there is a 'None' entry, return an error.
    if seed_phrase_options.iter().any(|option| option.is_none()) {
        Err("Encountered an invalid seed phrase in the file.".into())
    } else {
        // Otherwise, remove the 'None' entries and return the seed phrases.
        Ok(seed_phrase_options
            .into_iter()
            .flatten()
            .collect::<Vec<SeedPhrase>>())
    }
}

/// The function reads multiple seed phrases interactively.
///
/// The function reads lines from standard input and returns all collected seed phrases in a
/// vector of [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) struct if possible.
fn read_seed_phrases_interactively() -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
    let mut seed_phrases = vec![];
    let mut seed_phrase_string = String::new();
    // Read the first seed phrase from standard input.
    println!("Please enter the first secret-shared seed phrase (12, 15, 18, 21, or 24 space-delimited words):");
    let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    match convert_string_to_seed_phrase(&seed_phrase_string) {
        Some(seed_phrase) => seed_phrases.push(seed_phrase),
        None => return Err("Could not convert the input into a seed phrase.".into()),
    }
    seed_phrase_string.clear();
    // Read the next seed phrase from standard input.
    println!();
    println!("Please enter the next secret-shared seed phrase (press enter when done):");
    let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    while let Some(seed_phrase) = convert_string_to_seed_phrase(&seed_phrase_string) {
        seed_phrases.push(seed_phrase);
        seed_phrase_string.clear();
        println!();
        println!("Please enter the next secret-shared seed phrase (press enter when done):");
        let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    }
    Ok(seed_phrases)
}

/// The function handles the reconstruction of a seed phrase.
///
/// The input to the function is the command-line arguments. If processing succeeds,
/// the function returns the reconstructed [SeedPhrase](./seed_phrase/struct.SeedPhrase.html).
///
/// * `command_line` - The command-line arguments.
fn handle_reconstruct(command_line: &clap::ArgMatches) -> Result<SeedPhrase, Box<dyn Error>> {
    // Read the input fropm a file or interactively.
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
///
/// Given the command-line arguments, the main function triggers the processing of the
/// provided subcommand.
fn main() {
    // Get all command_line arguments.
    let command_line = parse_command_line();
    // Trigger the right function based on the provided subcommand.
    match command_line.subcommand_name() {
        Some(CREATE_SUBCOMMAND) => {
            match handle_create(
                &command_line
                    .subcommand_matches(CREATE_SUBCOMMAND)
                    .expect("The 'create' command must be specififed."),
            ) {
                Ok(seed_phrases) => {
                    println!();
                    println!("Created secret-shared seed phrases:");
                    println!("-----------------------------------");
                    for seed_phrase in seed_phrases {
                        println!("{}", seed_phrase);
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
                Ok(seed_phrase) => {
                    println!();
                    println!("Reconstructed seed phrase:");
                    println!("--------------------------");
                    println!("{}", seed_phrase)
                }
                Err(err) => println!("Error: {}", err),
            };
        }
        _ => println!("Error: A subcommand must be provided. Use --help to view options."),
    };
}
