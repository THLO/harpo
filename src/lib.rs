//! <h1>harpo</h1>
//!

//! The `harpo` crate provides functionality to secret-share seed phrases.
//!
//! The main functions that `harpo` provides are:
//! * [create_secret_shared_seed_phrases](crate::create_secret_shared_seed_phrases):
//!   Given a seed phrase, create the requested number of
//!   secret-shared seed phrases. A threshold must be provided as well, specifying how many
//!   secret-shared seed phrases are required to reconstruct the original seed phrase.
//! * [reconstruct_seed_phrase](crate::reconstruct_seed_phrase): Given a set of
//!   secret-shared seed phrases, the function
//!   reconstruct a seed phrase.
//!
//! The additional functionality that is provided is documented below.
//!

/// The math module provides the required finite field operations.
mod math;

// The seed phrase module provides the conversion between seed phrases and the representation as
// a finite field element.
pub mod seed_phrase;

/// The secret_sharing module provides the secret-sharing functionality.
mod secret_sharing;

/// The default word list is loaded from the word list module.
mod word_list;

use secret_sharing::{reconstruct_secret, SecretPolynomial, SecretShare};
use seed_phrase::{
    get_element_and_index_for_seed_phrase, get_element_for_seed_phrase, get_random_seed_phrase,
    get_seed_phrase_for_element, get_seed_phrase_for_element_with_embedding, is_compliant,
    SeedPhrase, NUM_BITS_FOR_INDEX,
};
use std::collections::HashSet;
use std::fmt::Display;
use word_list::DEFAULT_WORD_LIST;

/// The maximum number of shares that can be embedded.
/// It is `2^NUM_BITS_FOR_INDEX = 16`because 4 bits are used to encode the index in the embedding. It is not easily
/// possible to use more than 4 bits because only 4 additional bits are used when using a 12-word
/// seed phrase (12*11 = 132 bits to encode a secret of 128 bits).
const MAX_EMBEDDED_SHARES: usize = 1 << NUM_BITS_FOR_INDEX;

/// Every word list must have exactly this number of words.
const NUM_WORDS_IN_LIST: usize = 2048;

/// This enumeration type is returned by the main library functions if there is an error.
#[derive(Debug)]
pub enum HarpoError {
    /// This variant is used if the error relates to a seed phrase.
    InvalidSeedPhrase(String),
    /// This variant is used if the error relates to a parameter.
    InvalidParameter(String),
    /// This variant is used if there is an I/O error.
    IoError(std::io::Error),
    /// This variant is used if there is an error parsing an integer.
    ParseIntError(std::num::ParseIntError),
}

impl Display for HarpoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarpoError::InvalidSeedPhrase(message) => {
                write!(f, "Invalid seed phrase error: {}", message)
            }
            HarpoError::InvalidParameter(message) => {
                write!(f, "Invalid parameter error: {}", message)
            }
            HarpoError::IoError(error) => write!(f, "IO error: {}", error),
            HarpoError::ParseIntError(error) => write!(f, "Parsing error: {}", error),
        }
    }
}

impl From<std::io::Error> for HarpoError {
    /// The function defines how an [IO error](std::io::Error) is mapped to a
    /// [HarpoError](crate::HarpoError).
    ///
    /// * `err` - The IO error.
    fn from(err: std::io::Error) -> Self {
        HarpoError::IoError(err)
    }
}

impl From<std::num::ParseIntError> for HarpoError {
    /// The function defines how a [parse int error](std::num::ParseIntError) is mapped to a
    /// [HarpoError](crate::HarpoError).
    ///
    /// * `err` - The IO error.
    fn from(err: std::num::ParseIntError) -> Self {
        HarpoError::ParseIntError(err)
    }
}

/// A result that contains a [HarpoError](crate::HarpoError) in the `Err` case.
pub type HarpoResult<R> = Result<R, HarpoError>;

/// A [HarpoResult](crate::HarpoResult) that encapsulates a
/// [SeedPhrase](crate::seed_phrase::SeedPhrase) in the `Ok` case.
pub type SeedPhraseResult = HarpoResult<SeedPhrase>;

/// The function is called to create secret-shared seed phrases.
///
/// Given a seed phrase, threshold, and total number of secret-shared seed phrases,
/// the function returns a vector of seed phrases. The vector size corresponds to the
/// specified total number of seed phrases.
/// Each returned seed phrase has an associated index, which can be embedded in the
/// seed phrase itself or made available through the `index` field of
/// [SeedPhrase](crate::seed_phrase::SeedPhrase).
/// The flag `embed_indices` is used to specify how to handle indices.
///
/// * `seed_phrase` - The input seed phrase.
/// * `threshold` - The threshold.
/// * `num_seed_phrases` - The number of seed phrases.
/// * `embed_indices` - Flag indicating whether seed phrase indices should be embedded.
pub fn create_secret_shared_seed_phrases(
    seed_phrase: &SeedPhrase,
    threshold: usize,
    num_seed_phrases: usize,
    embed_indices: bool,
) -> HarpoResult<Vec<SeedPhrase>> {
    // Create the seed phrases using the default word list.
    create_secret_shared_seed_phrases_for_word_list(
        seed_phrase,
        threshold,
        num_seed_phrases,
        embed_indices,
        &DEFAULT_WORD_LIST,
    )
}

/// The function is called to create secret-shared seed phrases.
///
/// Given a seed phrase, threshold, total number of secret-shared seed phrases, and a word list,
/// the function returns a vector of seed phrases. The vector size corresponds to the
/// specified total number of seed phrases.
/// Each returned seed phrase has an associated index, which can be embedded in the
/// seed phrase itself or made available through the `index` field of
/// [SeedPhrase](crate::seed_phrase::SeedPhrase).
/// The flag `embed_indices` is used to specify how to handle indices.
///
/// * `seed_phrase` - The input seed phrase.
/// * `threshold` - The threshold.
/// * `num_seed_phrases` - The number of seed phrases.
/// * `embed_indices` - Flag indicating whether seed phrase indices should be embedded.
/// * `word_list` - The word list for the seed phrases.
pub fn create_secret_shared_seed_phrases_for_word_list(
    seed_phrase: &SeedPhrase,
    threshold: usize,
    num_shares: usize,
    embed_indices: bool,
    word_list: &[&str],
) -> HarpoResult<Vec<SeedPhrase>> {
    // Make sure that the word list contains the right number of words:
    if word_list.len() != NUM_WORDS_IN_LIST {
        return Err(HarpoError::InvalidSeedPhrase(format!(
            "The word list contains {} words instead of {}.",
            word_list.len(),
            NUM_WORDS_IN_LIST
        )));
    }
    // Make sure that the threshold is not greater than the number of shares.
    if threshold > num_shares {
        return Err(HarpoError::InvalidParameter(
            "The threshold must not exceed the number of secret-shared seed phrases.".to_string(),
        ));
    }
    // Make sure that the threshold at least 1.
    if threshold < 1 {
        return Err(HarpoError::InvalidParameter(
            "The threshold must be at least 1.".to_string(),
        ));
    }
    // Embedding is only possible if there are at most `MAX_EMBEDDED_SHARES` shares.
    if (num_shares > MAX_EMBEDDED_SHARES) && embed_indices {
        return Err(HarpoError::InvalidParameter(format!(
            "Only {} secret-shared pass phrases can be created with embedded indices.\n\
            Use a smaller number of shares or turn of index embedding ('--no-embedding').",
            MAX_EMBEDDED_SHARES
        )));
    }
    // Make sure that the seed phrase is BIP-0039 compliant.
    if !is_compliant(seed_phrase, word_list) {
        return Err(HarpoError::InvalidSeedPhrase(
            "The seed phrase is not BIP-0039 compliant.".to_string(),
        ));
    }
    // Turn the seed_phrase into a finite field element.
    let secret = get_element_for_seed_phrase(seed_phrase, word_list)?;
    // The degree is 1 lower than the threshold.
    let degree = threshold - 1;
    // Get the number of bits of security.
    let num_bits = seed_phrase.get_num_bits();
    // Create a secret polynomial (note that degree = threshold - 1).
    match SecretPolynomial::new(&secret, num_bits, degree) {
        Some(polynomial) => {
            // Create the secret shares for the finite field element.
            let secret_shares = polynomial.get_secret_shares(num_shares as u32);
            // Turn the secret shares into seed phrases and return them.
            let mut seed_phrases = vec![];
            for share in secret_shares {
                let element = get_seed_phrase_for_element_with_embedding(
                    &share.element,
                    Some(share.index),
                    embed_indices,
                    word_list,
                )?;
                seed_phrases.push(element);
            }
            Ok(seed_phrases)
        }
        None => Err(HarpoError::InvalidParameter(
            "Could not instantiate the required secret polynomial.".to_string(),
        )),
    }
}

/// The function is called to reconstruct a seed phrase.
///
/// Given a list of secret-shared seed phrases, the function
/// reconstructs the seed phrase that was originally used to generate the given seed phrases.
///
/// * `seed_phrases` - The input seed phrases.
/// * `word_list` - The word list for the seed phrases.
pub fn reconstruct_seed_phrase(seed_phrases: &[SeedPhrase]) -> SeedPhraseResult {
    // Reconstruct the seed phrase using the default word list.
    reconstruct_seed_phrase_for_word_list(seed_phrases, &DEFAULT_WORD_LIST)
}

/// The function is called to reconstruct a seed phrase.
///
/// Given a list of secret-shared seed phrases and a list of permissible words, the function
/// reconstructs the seed phrase that was originally used to generate the given seed phrases.
///
/// * `seed_phrases` - The input seed phrases.
/// * `word_list` - The word list for the seed phrases.
pub fn reconstruct_seed_phrase_for_word_list(
    seed_phrases: &[SeedPhrase],
    word_list: &[&str],
) -> SeedPhraseResult {
    // Make sure that the word list contains the right number of words:
    if word_list.len() != NUM_WORDS_IN_LIST {
        return Err(HarpoError::InvalidSeedPhrase(format!(
            "The word list contains {} words instead of {}.",
            word_list.len(),
            NUM_WORDS_IN_LIST
        )));
    }
    // Ensure that all seed phrases have the same length and that the length is valid.
    if seed_phrases.is_empty() {
        return Err(HarpoError::InvalidSeedPhrase(
            "No seed phrases provided.".to_string(),
        ));
    }
    let num_words = seed_phrases[0].len();
    if !(12..=24).contains(&num_words) || num_words % 3 != 0 {
        return Err(HarpoError::InvalidSeedPhrase(
            "Invalid number of words.".to_string(),
        ));
    }
    if seed_phrases.iter().any(|code| code.len() != num_words) {
        Err(HarpoError::InvalidSeedPhrase(
            "Found seed phrases with different lengths.".to_string(),
        ))
    } else {
        // Get the corresponding secret shares.
        let mut secret_shares = vec![];
        // Create a hash set of indices.
        let mut indices = HashSet::new();
        for seed_phrase in seed_phrases {
            let (element, index) = get_element_and_index_for_seed_phrase(seed_phrase, word_list)?;
            if !indices.contains(&index) {
                secret_shares.push(SecretShare::new(&element, index));
                indices.insert(index);
            }
        }
        // Reconstruct the secret element.
        let secret_element = reconstruct_secret(&secret_shares);
        // Turn the secret element into a seed phrase.
        get_seed_phrase_for_element(&secret_element, word_list)
    }
}

/// The function generates and returns a random seed phrase.
///
/// A random, BIP-0039 compliant seed phrase is returned if the requested number of words is
/// valid.
///
/// * `num_words` - The number of words in the seed phrase.
/// * `word_list` - The word list to be used.
pub fn generate_seed_phrase_for_word_list(
    num_words: usize,
    word_list: &[&str],
) -> SeedPhraseResult {
    get_random_seed_phrase(num_words, word_list)
}

/// The function generates and returns a random seed phrase.
///
/// A random, BIP-0039 compliant seed phrase is returned if the requested number of words is
/// valid.
///
/// * `num_words` - The number of words in the seed phrase.
pub fn generate_seed_phrase(num_words: usize) -> SeedPhraseResult {
    generate_seed_phrase_for_word_list(num_words, &DEFAULT_WORD_LIST)
}

// ******************************** TESTS ********************************

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{seq::SliceRandom, Rng};

    /// The different number of seed phrase lengths is 5 (12, 15, 18, 21, 24).
    const NUM_SEED_PHRASE_LENGTHS: usize = 5;

    /// The number of test runs.
    const NUM_TEST_RUNS: usize = 10;

    /// The maximum number of secret-shared seed phrases in the test runs.
    const MAX_NUM_SEED_PHRASES: usize = 64;

    #[test]
    /// The function provides basic tests for the create function.
    fn test_create_secret_shared_seed_phrases() {
        let words = [
            "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
            "winner", "thank", "yellow",
        ];
        let seed_phrase =
            SeedPhrase::new(&words.iter().map(|s| s.to_string()).collect::<Vec<String>>());
        let seed_phrases = create_secret_shared_seed_phrases(&seed_phrase, 2, 3, true);
        // Assert that there are seed phrases.
        assert!(seed_phrases.is_ok());
        // Assert that the right number of seed phrases is returned.
        assert_eq!(seed_phrases.unwrap().len(), 3);
        // Change the last word, making it an invalid seed phrase.
        let words = [
            "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
            "winner", "thank", "above",
        ];
        let seed_phrase =
            SeedPhrase::new(&words.iter().map(|s| s.to_string()).collect::<Vec<String>>());
        let seed_phrases = create_secret_shared_seed_phrases(&seed_phrase, 2, 3, true);
        // Assert that an error is returned.
        assert!(seed_phrases.is_err());
    }

    #[test]
    /// The function provides basic tests for the reconstruct function.
    fn test_reconstruct_seed_phrase() {
        // Create two seed phrases.
        let first_words = [
            "coil", "reunion", "immune", "ignore", "custom", "gallery", "dutch", "trouble",
            "snake", "ball", "wrong", "bike",
        ];
        let second_words = [
            "stable", "biology", "key", "post", "fiction", "concert", "hill", "step", "vibrant",
            "ocean", "punch", "car",
        ];
        let first_seed_phrase = SeedPhrase::new(
            &first_words
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );
        let second_seed_phrase = SeedPhrase::new(
            &second_words
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );

        let seed_phrases = [first_seed_phrase, second_seed_phrase];
        // Reconstruct the seed phrase.
        let seed_phrase = reconstruct_seed_phrase(&seed_phrases);
        // Assert that a seed phrase is returned.
        assert!(seed_phrase.is_ok());
        // Assert that it matches the expected seed phrase.
        let expected_words = [
            "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid",
            "letter", "advice", "cage", "above",
        ];
        let expected_seed_phrase = SeedPhrase::new(
            &expected_words
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );
        assert_eq!(seed_phrase.unwrap(), expected_seed_phrase);
    }

    #[test]
    /// The function tests the reconstruction of secret-shared seed phrases derived from
    /// a randomly generated seed phrase.
    fn test_random_seed_phrase_reconstruction() {
        // The valid number of words.
        let valid_num_words: [usize; NUM_SEED_PHRASE_LENGTHS] = [12, 15, 18, 21, 24];
        let mut rng = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            // Choose a random number of words.
            let num_words = valid_num_words
                .choose(&mut rng)
                .expect("A valid random number of words should be chosen.");
            // Generate a random seed phrase.
            let seed_phrase = generate_seed_phrase(*num_words)
                .expect("The generation of a seed phrase should work.");
            // Determine randomly if indices should be embedded.
            let embed_indices = rng.gen::<bool>();
            // Get a random number of secret-shared seed phrases parameter.
            let num_seed_phrases = match embed_indices {
                true => rng.gen_range(2..MAX_EMBEDDED_SHARES),
                false => rng.gen_range(2..MAX_NUM_SEED_PHRASES),
            };
            // Get the random threshold.
            let threshold = rng.gen_range(2..num_seed_phrases + 1);
            // Create the secret-shard seed phrases.
            let seed_phrases = create_secret_shared_seed_phrases(
                &seed_phrase,
                threshold,
                num_seed_phrases,
                embed_indices,
            )
            .expect("The creation of secret-shared seed phrases should work.");
            // Choose sufficiently many seed phrases.
            let num_selected = rng.gen_range(threshold..num_seed_phrases + 1);
            let selected_seed_phrases: Vec<SeedPhrase> = seed_phrases
                .choose_multiple(&mut rng, num_selected)
                .cloned()
                .collect();
            // Reconstruct the original seed phrase.
            let reconstructed_seed_phrase = reconstruct_seed_phrase(&selected_seed_phrases)
                .expect("The reconstruction of a seed-phrase should work.");
            // Assert that the original and reconstructed seed phrases are identical.
            assert_eq!(seed_phrase, reconstructed_seed_phrase);
            // Choose a number of seed phrases below the threshold.
            let num_selected = rng.gen_range(1..threshold);
            let selected_seed_phrases: Vec<SeedPhrase> = seed_phrases
                .choose_multiple(&mut rng, num_selected)
                .cloned()
                .collect();
            // Attempt to reconstruct the original seed phrase.
            let reconstructed_seed_phrase = reconstruct_seed_phrase(&selected_seed_phrases)
                .expect("The reconstruction of a seed-phrase should work.");
            // Assert that the original and reconstructed seed phrases are not identical.
            assert_ne!(seed_phrase, reconstructed_seed_phrase);
        }
    }
}
