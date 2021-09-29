/// The math module provides the required finite field operations.
mod math;

// The mnemonic module provides the conversion between mnemonic codes and the representation as
// a finite field element.
pub mod mnemonic;

/// The secret_sharing module provides the secret-sharing functionality.
mod secret_sharing;

/// The default word list is loaded from a separate module.
mod word_list;

use mnemonic::{
    get_element_for_mnemonic_code, get_mnemonic_code_for_element, MnemonicCode,
};
use secret_sharing::SecretPolynomial;
use std::error::Error;
use word_list::DEFAULT_WORD_LIST;

/// The function is called to create secret-shared mnemonic codes.
pub fn create_secret_shared_mnemonic_codes(
    mnemonic_code: &MnemonicCode,
    threshold: usize,
    num_shares: usize,
    embed_indices: bool,
) -> Result<Vec<MnemonicCode>, Box<dyn Error>> {
    // Create the mnemonic codes using the default word list.
    create_secret_shared_mnemonic_codes_for_word_list(
        mnemonic_code,
        threshold,
        num_shares,
        embed_indices,
        &DEFAULT_WORD_LIST,
    )
}

/// The function is called to create secret-shared mnemonic codes using the given word list.
pub fn create_secret_shared_mnemonic_codes_for_word_list(
    mnemonic_code: &MnemonicCode,
    threshold: usize,
    num_shares: usize,
    embed_indices: bool,
    word_list: &[&str],
) -> Result<Vec<MnemonicCode>, Box<dyn Error>> {
    //Make sure that the threshold is not greater than the number of shares.
    if threshold > num_shares {
        return Err(
            "Error: The threshold must not exceed the number of secret-shared mnemonic codes"
                .into(),
        );
    }
    // Turn the mnemonic_code into a finite field element.
    let secret = get_element_for_mnemonic_code(mnemonic_code, word_list)?;
    // The degree is 1 lower than the threshold.
    let degree = threshold - 1;
    // Get the number of bits of security.
    let num_bits = mnemonic_code.get_num_bits();
    // Create a secret polynomial (note that degree = threshold - 1).
    match SecretPolynomial::new(&secret, num_bits, degree) {
        Some(polynomial) => {
            // Create the secret shares for the finite field element.
            let secret_shares = polynomial.get_secret_shares(num_shares as u32);
            // Turn the secret shares into mnemonic codes and return them.
            let mut mnemonic_codes = vec![];
            for share in secret_shares {
                let element =
                    get_mnemonic_code_for_element(&share.element, Some(share.index), embed_indices, word_list)?;
                mnemonic_codes.push(element);
            }
            Ok(mnemonic_codes)
        }
        None => Err("Error: Could not instantiate the required secret polynomial.".into()),
    }
}

pub fn reconstruct_mnemonic_code(
    mnemonic_codes: &[MnemonicCode],
) -> Result<MnemonicCode, Box<dyn Error>> {
    // Reconstruct the mnemonic code using the default word list
    reconstruct_mnemonic_code_for_word_list(mnemonic_codes, &DEFAULT_WORD_LIST)
}

/// The function is called to reconstruct a mnemonic code.
pub fn reconstruct_mnemonic_code_for_word_list(
    mnemonic_codes: &[MnemonicCode],
    word_list: &[&str],
) -> Result<MnemonicCode, Box<dyn Error>> {
    // Ensure that all mnemonic codes have the same length and that the length is valid.
    if mnemonic_codes.is_empty() {
        return Err("Error: No mnemonic codes provided.".into());
    }
    let num_words = mnemonic_codes[0].len();
    if !(12..=24).contains(&num_words) || num_words % 3 != 0 {
        return Err("Error: Invalid number of words.".into());
    }
    if let Some(entry) = mnemonic_codes.iter().find(|code| code.len() != num_words) {
        Err("Found mnemonic codes with different lenghts.".into())
    } else {
        // Get the corresponding secret shares.
        Err("Not implemented yet!".into())
    }
}
