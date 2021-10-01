//! <h1>harpo</h1>
//!

//! The `harpo` crate provides functionality to secret-share seed phrases.
//!
//! The main functions that `harpo` provides are:
//! * [create_secret_shared_seed_phrases](fn.create_secret_shared_seed_phrases.html):
//!   Given a seed phrase, create the requested number of
//!   secret-shared seed phrases. A threshold must be provided as well, specifying how many
//!   secret-shared seed phrases are required to reconstruct the original seed phrase.
//! * [reconstruct_seed_phrase](fn.econstruct_seed_phrase.html): Given a set of
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
    get_seed_phrase_for_element, get_seed_phrase_for_element_with_embedding, SeedPhrase,
};
use std::collections::HashSet;
use std::error::Error;
use word_list::DEFAULT_WORD_LIST;

/// The function is called to create secret-shared seed phrases.
///
/// Given a seed phrase, threshold, and total number of secret-shared seed phrases,
/// the function returns a vector of seed phrases. The vector size corresponds to the
/// specified total number of seed phrases.
/// Each returned seed phrase has an associated index, which can be embedded in the
/// seed phrase itself or made available through the `index` field of
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html).
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
/// [SeedPhrase](./seed_phrase/struct.SeedPhrase.html).
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
