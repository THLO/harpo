//! The `main` defines the command-line interface and interacts with the `lib` module
//! to provide access to all publicly accessible functionality of the `harpo` crate.
//!

extern crate clap;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use harpo::seed_phrase::SeedPhrase;
use harpo::{
    create_secret_shared_seed_phrases, create_secret_shared_seed_phrases_for_word_list,
    generate_seed_phrase, generate_seed_phrase_for_word_list, reconstruct_seed_phrase,
    reconstruct_seed_phrase_for_word_list, HarpoError, HarpoResult, SeedPhraseResult,
};
use std::fs::read_to_string;

/// The subcommand to create secret-shared seed phrases.
const CREATE_SUBCOMMAND: &str = "create";

/// The subcommand to reconstruct a seed phrase.
const RECONSTRUCT_SUBCOMMAND: &str = "reconstruct";

/// The subcommand to generate a seed phrase.
const GENERATE_SUBCOMMAND: &str = "generate";

/// The function parses the command-line arguments.
fn parse_command_line<'a>() -> ArgMatches<'a> {
    // Extract version and author from the Cargo.toml file.
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

    // The arguments that the create and reconstruct subcommands share are defined first.

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

    // The generate subcommand.
    let generate_subcommand = SubCommand::with_name(GENERATE_SUBCOMMAND)
        .about("Generates a seed phrase")
        .arg(
            Arg::with_name("length") // The number of words.
                .required(true)
                .takes_value(true)
                .short("l")
                .long("length")
                .help("Sets the number of words to the given value"),
        );

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
        .arg(
            Arg::with_name("word-list") // A word-list file can be provided.
                .short("w")
                .long("word-list")
                .help("Reads the word list from the provided file")
                .takes_value(true),
        )
        .subcommand(create_subcommand) // Add the create subcommand.
        .subcommand(reconstruct_subcommand) // Add the reconstruct subcommand.
        .subcommand(generate_subcommand) // Add the generate subcommand.
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
fn convert_string_to_seed_phrase(input: &str) -> SeedPhraseResult {
    // Break the input into words.
    let mut words: Vec<String> = input
        .replace(':', ": ") // If there is an index, ensure that it is a separate word.
        .to_lowercase() // No upper-case words are allowed.
        .trim() // Remove white spaces in the beginning and at the end.
        .split(' ') // Split the string.
        .filter(|word| !word.is_empty()) // Keep only words with a positive length.
        .map(str::to_string) // Map the string slices to strings.
        .collect(); // Collect the vector.
    if words.is_empty() {
        // Make sure that there are sufficiently many words.
        return Err(HarpoError::InvalidSeedPhrase(
            "No seed phrase provided.".to_string(),
        ));
    }
    // If there is an explicit index, extract it from the list of words.
    if words[0].contains(':') {
        let index_string = words.remove(0);
        match index_string.replace(":", "").parse::<u32>() {
            Ok(index) => Ok(SeedPhrase::new_with_index(&words, index)),
            Err(_) => Err(HarpoError::InvalidSeedPhrase(
                "Could not parse index of seed phrase.".to_string(),
            )),
        }
    } else {
        // Otherwise, create a seed phrase without an index.
        Ok(SeedPhrase::new(&words))
    }
}

/// The function reads a seed phrase from the given file.
///
/// The function takes a file path argument and reads in a
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) if possible.
///
/// * `file_path` - The path to the file containing the seed phrase.
fn read_seed_phrase_from_file(file_path: &str) -> SeedPhraseResult {
    // Read the file content.
    let file_content = read_to_string(file_path)?;
    // Find a line that might encode a seed phrase.
    let seed_phrase_string = file_content
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty());
    // If a seed phrase is found, turn the string into a SeedPhrase struct and return it.
    match seed_phrase_string {
        Some(seed_phrase_string) => convert_string_to_seed_phrase(seed_phrase_string),
        None => Err(HarpoError::InvalidSeedPhrase(format!(
            "Could not read the seed phrase from the file {}.",
            file_path
        ))),
    }
}

/// The function reads a seed phrase from standard input.
///
/// The function reads a line from standard input and returns it as a
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) if possible.
fn read_seed_phrase_interactively() -> SeedPhraseResult {
    let mut seed_phrase_string = String::new();
    println!("Please enter your seed phrase (12, 15, 18, 21, or 24 space-delimited words):");
    // Read from standard input.
    let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    // If the input can be converted to a seed phrase, return the seed phrase.
    convert_string_to_seed_phrase(&seed_phrase_string)
}

/// The function handles the creation of secret-shared seed phrases.
///
/// The input to the function is the command-line arguments. If processing succeeds,
/// the function returns a vector of [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) structs.
///
/// * `command_line` - The command-line arguments.
/// * `verbose` - Flag indicating if verbose output should be generated.
fn handle_create(
    command_line: &clap::ArgMatches,
    verbose: bool,
    word_list: Option<Vec<String>>,
) -> HarpoResult<Vec<SeedPhrase>> {
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
    // Print verbose output if the flag --verbose is set.
    if verbose {
        println!(
            "Requested number of secret-shared seed phrases: {}",
            num_shares
        );
        println!("Requested threshold for reconstruction: {}", threshold);
        println!();
    }
    // Read the input from a file or interactively.
    let seed_phrase = if let Some(file_path) = command_line.value_of("file") {
        if verbose {
            println!("Reading the seed phrase from {}...", file_path);
        }
        read_seed_phrase_from_file(file_path)?
    } else {
        // The seed phrase must be entered interactively.
        read_seed_phrase_interactively()?
    };
    // Get the --no-embedding flag.
    let embed_indices = !command_line.is_present("no-embedding");
    // Create the shares and return them.
    if verbose {
        println!();
        println!(
            "Creating secret-shared seed phrases for seed phrase '{}'...",
            seed_phrase
        );
    }
    // Call the right library function.
    match word_list {
        Some(list) => {
            let slice_list: Vec<&str> = list.iter().map(|s| s.as_str()).collect();
            create_secret_shared_seed_phrases_for_word_list(
                &seed_phrase,
                threshold,
                num_shares,
                embed_indices,
                &slice_list,
            )
        }
        None => {
            create_secret_shared_seed_phrases(&seed_phrase, threshold, num_shares, embed_indices)
        }
    }
}

/// The function reads multiple seed phrases from a file.
///
/// The function takes a file path argument and reads in all seed phrases.
/// If processing succeeds, a vector of
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html) is returned.
///
/// * `file_path` - The path to the file containing the seed phrases.
fn read_seed_phrases_from_file(file_path: &str) -> HarpoResult<Vec<SeedPhrase>> {
    // Read the file content.
    let file_content = read_to_string(file_path)?;
    // Get all potential seed phrases.
    let seed_phrase_options: Vec<SeedPhraseResult> = file_content
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| convert_string_to_seed_phrase(line))
        .collect();
    // If there is a 'None' entry, return an error.
    if seed_phrase_options.iter().any(|option| option.is_err()) {
        Err(HarpoError::InvalidSeedPhrase(
            "Encountered an invalid seed phrase in the file.".to_string(),
        ))
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
fn read_seed_phrases_interactively() -> HarpoResult<Vec<SeedPhrase>> {
    let mut seed_phrases = vec![];
    let mut seed_phrase_string = String::new();
    // Read the first seed phrase from standard input.
    println!("Please enter the first secret-shared seed phrase (12, 15, 18, 21, or 24 space-delimited words):");
    let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    match convert_string_to_seed_phrase(&seed_phrase_string) {
        Ok(seed_phrase) => seed_phrases.push(seed_phrase),
        Err(e) => return Err(e),
    }
    seed_phrase_string.clear();
    // Read the next seed phrase from standard input.
    println!();
    println!("Please enter the next secret-shared seed phrase (press enter when done):");
    let _ = std::io::stdin().read_line(&mut seed_phrase_string)?;
    while let Ok(seed_phrase) = convert_string_to_seed_phrase(&seed_phrase_string) {
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
/// * `verbose` - Flag indicating if verbose output should be generated.
fn handle_reconstruct(
    command_line: &clap::ArgMatches,
    verbose: bool,
    word_list: Option<Vec<String>>,
) -> SeedPhraseResult {
    // Read the input from a file or interactively.
    let seed_phrases = if let Some(file_path) = command_line.value_of("file") {
        // Print verbose output if the flag --verbose is set.
        if verbose {
            println!("Reading seed phrases from {}...", file_path);
            println!();
        }
        read_seed_phrases_from_file(file_path)?
    } else {
        // The seed phrases must be entered interactively.
        read_seed_phrases_interactively()?
    };
    if verbose {
        println!(
            "Reconstructing the seed phrase using these {} seed phrases:",
            seed_phrases.len()
        );
        println!();
        for seed_phrase in &seed_phrases {
            println!("{}", seed_phrase);
        }
    }
    // Reconstruct the seed phrase.
    match word_list {
        Some(list) => {
            let slice_list: Vec<&str> = list.iter().map(|s| s.as_str()).collect();
            reconstruct_seed_phrase_for_word_list(&seed_phrases, &slice_list)
        }
        None => reconstruct_seed_phrase(&seed_phrases),
    }
}

/// The function attempts to read a word list from the provided file path.
///
/// The function simply assumes that there is one word per line and builds a vector
/// of strings accordingly. There is no verification that a proper word list is processed.
///
/// * `file_path` - The path to the file containing the word list.
fn read_word_list_from_file(file_path: &str) -> HarpoResult<Vec<String>> {
    // Read the file content.
    let file_content = read_to_string(file_path)?;
    // Read the words, one per line.
    let word_list: Vec<String> = file_content.lines().map(str::to_string).collect();
    Ok(word_list)
}

fn handle_generate(
    command_line: &clap::ArgMatches,
    verbose: bool,
    word_list: Option<Vec<String>>,
) -> SeedPhraseResult {
    // Get the length of the word list. The unwrap() is okay because --length must be provided.
    let length = command_line.value_of("length").unwrap().parse::<usize>()?;
    if verbose {
        println!("Length of seed phrase: {}", length);
    }
    // Generate the seed phrase.
    match word_list {
        Some(list) => {
            let slice_list: Vec<&str> = list.iter().map(|s| s.as_str()).collect();
            generate_seed_phrase_for_word_list(length, &slice_list)
        }
        None => generate_seed_phrase(length),
    }
}

/// The main function uses the command-line arguments to trigger the right command execution.
///
/// Given the command-line arguments, the main function triggers the processing of the
/// provided subcommand.
fn main() {
    // Get all command_line arguments.
    let command_line = parse_command_line();
    // Check if the verbose flag is used.
    let verbose = command_line.is_present("verbose");
    // If a path to a word-list file is provided, try to load it.
    let word_list = match command_line.value_of("word-list") {
        Some(file_path) => {
            if verbose {
                println!("Word list file: {}", file_path);
            }
            match read_word_list_from_file(file_path) {
                Ok(list) => Some(list),
                Err(error) => {
                    eprintln!("{}", error);
                    return;
                }
            }
        }
        None => None,
    };
    // Trigger the right function based on the provided subcommand.
    match command_line.subcommand_name() {
        Some(CREATE_SUBCOMMAND) => {
            match handle_create(
                &command_line
                    .subcommand_matches(CREATE_SUBCOMMAND)
                    .expect("The 'create' command must be specified."),
                verbose,
                word_list,
            ) {
                Ok(seed_phrases) => {
                    println!();
                    println!("Created secret-shared seed phrases:");
                    println!("-----------------------------------");
                    for seed_phrase in seed_phrases {
                        println!("{}", seed_phrase);
                    }
                }
                Err(err) => {
                    println!();
                    eprintln!("{}", err);
                }
            };
        }
        Some(RECONSTRUCT_SUBCOMMAND) => {
            match handle_reconstruct(
                &command_line
                    .subcommand_matches(RECONSTRUCT_SUBCOMMAND)
                    .expect("Error: The 'create' command must be specified."),
                verbose,
                word_list,
            ) {
                Ok(seed_phrase) => {
                    println!();
                    println!("Reconstructed seed phrase:");
                    println!("--------------------------");
                    println!("{}", seed_phrase)
                }
                Err(err) => {
                    println!();
                    eprintln!("{}", err);
                }
            };
        }
        Some(GENERATE_SUBCOMMAND) => {
            match handle_generate(
                &command_line
                    .subcommand_matches(GENERATE_SUBCOMMAND)
                    .expect("Error: The 'generate' command must be specified."),
                verbose,
                word_list,
            ) {
                Ok(seed_phrase) => {
                    println!();
                    println!("Generated seed phrase:");
                    println!("----------------------");
                    println!("{}", seed_phrase)
                }
                Err(err) => {
                    println!();
                    eprintln!("{}", err);
                }
            };
        }
        _ => eprintln!("Error: A subcommand must be provided. Use --help to view options."),
    };
}
