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
    get_element_and_index_for_seed_phrase, get_element_for_seed_phrase,
    get_seed_phrase_for_element, get_seed_phrase_for_element_with_embedding, is_compliant,
    SeedPhrase, NUM_BITS_FOR_INDEX,
};
use std::collections::HashSet;
use std::error::Error;
use word_list::DEFAULT_WORD_LIST;

/// The maximum number of shares that can be embedded.
/// It is `2^NUM_BITS_FOR_INDEX = 16`because 4 bits are used to encode the index in the embedding. It is not easily
/// possible to use more than 4 bits because only 4 additional bits are used when using a 12-word
/// seed phrase (12*11 = 132 bits to encode a secret of 128 bits).
const MAX_EMBEDDED_SHARES: usize = 2 << NUM_BITS_FOR_INDEX;

/// Every word list must have exactly this number of words.
const NUM_WORDS_IN_LIST: usize = 2048;

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
) -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
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
) -> Result<Vec<SeedPhrase>, Box<dyn Error>> {
    // Make sure that the seed phrase is BIP-0039 compliant.
    if !is_compliant(seed_phrase, word_list) {
        return Err("The seed phrase is invalid.".into());
    }
    // Make sure that the word list contains the right number of words:
    if word_list.len() != NUM_WORDS_IN_LIST {
        return Err(format!(
            "The word list contains {} words instead of {}.",
            word_list.len(),
            NUM_WORDS_IN_LIST
        )
        .into());
    }
    // Make sure that the threshold is not greater than the number of shares.
    if threshold > num_shares {
        return Err(
            "The threshold must not exceed the number of secret-shared seed phrases.".into(),
        );
    }
    // Make sure that the threshold at least 1.
    if threshold < 1 {
        return Err("The threshold must be at least 1.".into());
    }
    // Embedding is only possible if there are at most `MAX_EMBEDDED_SHARES` shares.
    if num_shares > MAX_EMBEDDED_SHARES && embed_indices {
        return Err(format!(
            "Only {} secret-shared pass phrases can be created with embedded indices.\n\
            Use a smaller number of shares or turn of index embedding ('--no-embedding').",
            MAX_EMBEDDED_SHARES
        )
        .into());
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
        None => Err("Could not instantiate the required secret polynomial.".into()),
    }
}

/// The function is called to recontruct a seed phrase.
///
/// Given a list of secret-shared seed phrases, the function
/// reconstructs the seed phrase that was originally used to generate the given seed phrases.
///
/// * `seed_phrases` - The input seed phrases.
/// * `word_list` - The word list for the seed phrases.
pub fn reconstruct_seed_phrase(seed_phrases: &[SeedPhrase]) -> Result<SeedPhrase, Box<dyn Error>> {
    // Reconstruct the seed phrase using the default word list.
    reconstruct_seed_phrase_for_word_list(seed_phrases, &DEFAULT_WORD_LIST)
}

/// The function is called to recontruct a seed phrase.
///
/// Given a list of secret-shared seed phrases and a list of permissible words, the function
/// reconstructs the seed phrase that was originally used to generate the given seed phrases.
///
/// * `seed_phrases` - The input seed phrases.
/// * `word_list` - The word list for the seed phrases.
pub fn reconstruct_seed_phrase_for_word_list(
    seed_phrases: &[SeedPhrase],
    word_list: &[&str],
) -> Result<SeedPhrase, Box<dyn Error>> {
    // Make sure that the word list contains the right number of words:
    if word_list.len() != NUM_WORDS_IN_LIST {
        return Err(format!(
            "The word list contains {} words instead of {}.",
            word_list.len(),
            NUM_WORDS_IN_LIST
        )
        .into());
    }
    // Ensure that all seed phrases have the same length and that the length is valid.
    if seed_phrases.is_empty() {
        return Err("No seed phrases provided.".into());
    }
    let num_words = seed_phrases[0].len();
    if !(12..=24).contains(&num_words) || num_words % 3 != 0 {
        return Err("Invalid number of words.".into());
    }
    if seed_phrases.iter().any(|code| code.len() != num_words) {
        Err("Found seed phrases with different lengths.".into())
    } else {
        // Get the corresponding secret shares.
        let mut secret_shares = vec![];
        // Create a hash set of indices.
        let mut indices = HashSet::new();
        for code in seed_phrases {
            let (element, index) = get_element_and_index_for_seed_phrase(code, word_list)?;
            if !indices.contains(&index) {
                secret_shares.push(SecretShare::new(&element, index));
                indices.insert(index);
            }
        }
        // Recontruct the secret element.
        let secret_element = reconstruct_secret(&secret_shares);
        // Turn the secret element into a seed phrase.
        get_seed_phrase_for_element(&secret_element, word_list)
    }
}

// ******************************** TESTS ********************************

#[cfg(test)]
mod tests {
    use super::*;

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
}
