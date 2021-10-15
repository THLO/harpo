//! The `seed_phrase` module provides the functionality to convert a seed phrase into a finite
//! field element and vice versa.
//!

use crate::math::FiniteFieldElement;
use crate::secret_sharing::get_modulus_for_words;
use crate::word_list::DEFAULT_WORD_LIST;
use crate::{HarpoError, HarpoResult, SeedPhraseResult};
use sha2::{Digest, Sha256};
use std::cmp;
use std::fmt;

/// The number of bits that each word represents.
const NUM_BITS_PER_WORD: usize = 11;
/// The number of bits used to encode an index.
pub const NUM_BITS_FOR_INDEX: usize = 4;
/// The increase in the number of bits from one security level to the next.
const ENTROPY_INCREMENT: usize = 32;

/// This struct represents a seed phrase.
/// A seed phrase consists of a series of words and, optionally, an index.
/// The index is used to reconstruct secret-shared seed phrases.
#[derive(Eq, Debug)]
pub struct SeedPhrase {
    /// The words.
    words: Vec<String>,
    /// The optional index.
    index: Option<u32>,
}

impl SeedPhrase {
    /// The function creates a new seed phrase using the given words.
    ///
    /// The list of words is accepted as is, i.e., there is no verification whether
    /// the words comply with any standard (in particular BIP-0039).
    /// Since no index is provided, the seed phrase is considered not to have an index.
    ///
    /// * `words` - The words that make up the seed phrase.
    pub fn new(words: &[String]) -> Self {
        let internal_words: Vec<String> = words.to_vec();
        SeedPhrase {
            words: internal_words,
            index: None,
        }
    }

    /// The function creates a new seed phrase using the given words and index.
    ///
    /// The list of words is accepted as is, i.e., there is no verification whether
    /// the words comply with any standard (in particular BIP-0039).
    /// The index is the position in the list of secret-shared seed phrases.
    ///
    /// * `words` - The words that make up the seed phrase.
    /// * `index` - The index of the seed phrase.
    pub fn new_with_index(words: &[String], index: u32) -> Self {
        let internal_words: Vec<String> = words.to_vec();
        SeedPhrase {
            words: internal_words,
            index: Some(index),
        }
    }

    /// The function returns the number of words that make up the seed phrase.
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// The function returns true if the seed phrase is empty.
    pub fn is_empty(&self) -> bool {
        self.words.len() == 0
    }

    /// The function returns the words that make up the seed phrase.
    pub fn get_words(&self) -> Vec<&str> {
        self.words.iter().map(|s| s.as_str()).collect()
    }

    /// The function returns the index of the seed phrase, if any.
    pub fn get_index(&self) -> Option<u32> {
        self.index
    }

    /// The function returns the security level of the seed phrase in bits.
    pub fn get_num_bits(&self) -> usize {
        // The number of security bits is the total number of bits rounded down to the
        // nearest multiple of 'ENTROPY_INCREMENT'.
        ((self.words.len() * NUM_BITS_PER_WORD) / ENTROPY_INCREMENT) * ENTROPY_INCREMENT
    }
}

impl Clone for SeedPhrase {
    /// The function defines how a seed phrase is cloned.
    fn clone(&self) -> SeedPhrase {
        SeedPhrase {
            words: self.words.clone(),
            index: self.index,
        }
    }
}

impl fmt::Display for SeedPhrase {
    /// A seed phrase is displayed as a space-delimited string.
    /// If it has an associated index, the index followed by a colon is prepended to the
    /// list of words.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut words_with_spaces = String::new();
        // Create a space-delimited string of all words.
        for index in 0..(self.words.len() - 1) {
            words_with_spaces.push_str(&self.words[index]);
            words_with_spaces.push(' ');
        }
        words_with_spaces.push_str(&self.words[self.words.len() - 1]);
        // If there is an index, prepend it.
        match self.index {
            Some(index) => write!(f, "{}: {}", index, words_with_spaces),
            None => write!(f, "{}", words_with_spaces),
        }
    }
}

impl PartialEq for SeedPhrase {
    /// Equality of two seed phrases is defined based on the words that make up the seed phrases.
    fn eq(&self, other: &Self) -> bool {
        self.words == other.words
    }
}

pub(crate) fn get_random_seed_phrase(num_words: usize, word_list: &[&str]) -> SeedPhraseResult {
    if num_words % 3 != 0 || num_words < 12 || num_words > 24 {
        return Err(HarpoError::InvalidParameter(
            "The number of words must be 12, 15, 18, 21, or 24.".to_string(),
        ));
    }
    // Determine the number of bits based on the number of words.
    let num_bits = ((num_words * NUM_BITS_PER_WORD) / ENTROPY_INCREMENT) * ENTROPY_INCREMENT;
    // Get the modulus.
    match get_modulus_for_words(num_words) {
        Some(modulus) => {
            // Create a random finite field element.
            let element = FiniteFieldElement::new_random(num_bits, &modulus);
            // Return the seed phrase derived from this element.
            get_seed_phrase_for_element(&element, word_list)
        }
        None => Err(HarpoError::InvalidSeedPhrase(
            "Could not generate a seed phrase.".to_string(),
        )),
    }
}

/// The function returns the index of a word in a word list, if any.
///
/// The function searches for the given word in the given word list and returns the index
/// in the list if it finds it. Otherwise, it returns 'None'.
///
/// * `word` - The word that is looked up.
/// * `word_list` - The list of words.
fn get_index(word: &str, word_list: &[&str]) -> Option<usize> {
    // Use a standard binary search to look for the word if it is the English word list.
    // Otherwise, a linear search is used because string comparison fails when words contain
    // diacritics.
    if word_list[0] == DEFAULT_WORD_LIST[0] {
        let mut left = 0;
        let mut right = word_list.len() - 1;
        while left <= right {
            let mid = ((left + right) / 2) as usize;
            match word_list[mid] {
                w if w == word => return Some(mid),
                w if w < word => left = mid + 1,
                _ => right = mid - 1,
            };
        }
    } else {
        for (index, word) in word_list.iter().enumerate() {
            if &word_list[index] == word {
                return Some(index);
            }
        }
    }
    None
}

/// The function returns the finite field element corresponding to the given seed phrase.
///
/// Given a seed phrase and a word list, the words are turned into numbers, corresponding to their
/// indices in the word list, and the numbers are concatenated in a byte array.
/// The integer that defines the finite field element is extracted from these bytes.
///
/// * `seed_phrase` - The seed phrase.
/// * `word_list` - The word list.
pub(crate) fn get_element_for_seed_phrase(
    seed_phrase: &SeedPhrase,
    word_list: &[&str],
) -> HarpoResult<FiniteFieldElement> {
    // Get the element and discard the index.
    let (element, _) = get_element_and_index_for_seed_phrase(seed_phrase, word_list)?;
    // Return the corresponding finite field element.
    Ok(element)
}

// The function returns the index list for a given seed phrase.
//
// * `seed_phrase` - The seed phrase.
/// * `word_list` - The word list.
fn get_index_list(seed_phrase: &SeedPhrase, word_list: &[&str]) -> HarpoResult<Vec<usize>> {
    // Verify that the seed phrase has a permissible number of words.
    let num_words = seed_phrase.len();
    if num_words % 3 != 0 || num_words < 12 || num_words > 24 {
        return Err(HarpoError::InvalidParameter(
            "The number of words must be 12, 15, 18, 21, or 24.".to_string(),
        ));
    }
    let mut index_list: Vec<usize> = vec![];
    // Iterate through all the words and get the index, if available.
    for word in seed_phrase.get_words() {
        match get_index(word, word_list) {
            Some(index) => index_list.push(index),
            None => {
                return Err(HarpoError::InvalidSeedPhrase(format!(
                    "Invalid word in the seed phrase: {}",
                    word
                )))
            }
        };
    }
    Ok(index_list)
}

// The function checks BIP-0039 compliance of the seed phrase.
//
// The function checks whether the last word is the expected word according to the BIP-0039
// specification by examining the hash bits.
//
// * `seed_phrase` - The seed phrase.
pub(crate) fn is_compliant(seed_phrase: &SeedPhrase, word_list: &[&str]) -> bool {
    // The words are mapped to their indices in the word list.
    let index_list_result = get_index_list(seed_phrase, word_list);
    match index_list_result {
        Ok(index_list) => {
            // Convert the indices into a byte array.
            let bytes = get_bytes_from_indices(&index_list);
            // The number of bytes used to build the element is a multiple of 32 bits = 4 bytes.
            let num_used_bytes = (bytes.len() >> 2) << 2;
            // Copy the bytes into a new array.
            let mut used_bytes: Vec<u8> = vec![0; num_used_bytes];
            used_bytes.clone_from_slice(&bytes[0..num_used_bytes]);
            // Compute the SHA-256 hash of the bytes.
            let mut hasher = Sha256::new();
            hasher.update(&used_bytes);
            let hash = hasher.finalize();
            // The number of words.
            let num_words = seed_phrase.len();
            // The number of hash bits that are used.
            let num_hash_bits = NUM_BITS_PER_WORD * num_words - (num_used_bytes << 3);
            let num_zero_bits = 8 - num_hash_bits;
            // Set the unused bits to zero.
            let hash_byte = (hash[0] >> num_zero_bits) << num_zero_bits;
            // The seed phrase is valid if the hash bytes match the left-over byte.
            hash_byte == bytes[num_used_bytes]
        }
        Err(_) => false,
    }
}

/// The function returns the finite field element and index encoded in the given seed phrase.
///
/// Given a seed phrase and a word list, the words are turned into numbers, corresponding to their
/// indices in the word list, and the numbers are concatenated in a byte array.
/// The integer that defines the finite field element and the index of the finite field element are
/// extracted from these bytes.
///
/// * `seed_phrase` - The seed phrase.
/// * `word_list` - The word list.
pub(crate) fn get_element_and_index_for_seed_phrase(
    seed_phrase: &SeedPhrase,
    word_list: &[&str],
) -> HarpoResult<(FiniteFieldElement, u32)> {
    // The words are mapped to their indices in the word list.
    let index_list = get_index_list(seed_phrase, word_list)?;
    // Convert the indices into a byte array.
    let bytes = get_bytes_from_indices(&index_list);
    // The number of bytes used to build the element is a multiple of 32 bits = 4 bytes.
    let num_used_bytes = (bytes.len() >> 2) << 2;
    // Copy the bytes into a new array.
    let mut used_bytes: Vec<u8> = vec![0; num_used_bytes];
    used_bytes.clone_from_slice(&bytes[0..num_used_bytes]);
    // Get the number of words.
    let num_words = seed_phrase.len();
    // Get the modulus. Calling unwrap() is okay here because the number of words is checked
    // at the beginning of the function call.
    let modulus = get_modulus_for_words(num_words).unwrap();
    // Get the index.
    let index = if let Some(index) = seed_phrase.get_index() {
        index
    } else {
        // The index is encoded in the byte at index `num_used_bytes`.
        // We add 1 because 1 was subtracted when encoding the index.
        ((bytes[num_used_bytes] >> (8 - NUM_BITS_FOR_INDEX)) + 1) as u32
    };
    // Return the corresponding finite field element and index.
    Ok((FiniteFieldElement::new(&bytes, &modulus), index))
}

/// The function encodes the given indices in a byte array.
///
/// The indices are encoded in the byte array according to the BIP-0039 specification.
///
/// * `indices` - The array of indices.
fn get_bytes_from_indices(indices: &[usize]) -> Vec<u8> {
    // Round the number of bytes up so that there is space for all indices.
    let size = (indices.len() * NUM_BITS_PER_WORD + 7) / 8;
    // The bytes are written into this byte array.
    let mut bytes: Vec<u8> = vec![0; size];
    // The number of used bits in the current byte.
    let mut num_used_bits = 0;
    // The index of the currrent byte.
    let mut current_index = 0;
    // Iterate over all indices.
    for index in indices {
        // Determine the number of bits spread over two or three bytes.
        let num_bits_first_byte = 8 - num_used_bits;
        let num_bits_second_byte = cmp::min(8, 11 - num_bits_first_byte);
        let num_bits_third_byte = cmp::max(0, 11 - num_bits_first_byte - num_bits_second_byte);
        // Compute the part for the first byte.
        let first_byte_part = (index >> (11 - num_bits_first_byte)) as u8;
        bytes[current_index] += first_byte_part;
        current_index += 1;
        // Compute the part for the second byte.
        let second_byte_part = ((index >> num_bits_third_byte) % (1 << num_bits_second_byte)) as u8;
        bytes[current_index] = second_byte_part << (8 - num_bits_second_byte);
        // Check if there are remaining bits for the third byte.
        if num_bits_third_byte > 0 {
            current_index += 1;
            // The third part consists of the `num_bits_third_byte` lowest-order bits.
            let third_byte_part = (index % (1 << num_bits_third_byte)) as u8;
            // These bits are placed in the highest-order positions.
            bytes[current_index] = third_byte_part << (8 - num_bits_third_byte);
            num_used_bits = num_bits_third_byte;
        } else if num_bits_second_byte == 8 {
            // If the index exactly consumes all bits of the second byte,
            // the index is increased as the byte is full.
            current_index += 1;
            num_used_bits = 0;
        } else {
            // Otherwse, the number of used bits is the number of bits written to the
            // second byte.
            num_used_bits = num_bits_second_byte;
        }
    }
    // Return the byte array.
    bytes
}

/// The function converts a finite field element into a seed phrase without embedding an index.
///
/// This function is merely a convenience function, calling the function
/// `get_seed_phrase_for_element_with_embedding` with `index = None` and `embed_index = false`.
///
/// `number` - The finite field element.
/// `word_list` - The word list.
pub(crate) fn get_seed_phrase_for_element(
    element: &FiniteFieldElement,
    word_list: &[&str],
) -> SeedPhraseResult {
    get_seed_phrase_for_element_with_embedding(element, None, false, word_list)
}

/// The function converts a finite field element into a seed phrase.
///
/// In addition to the finite field element and the word list, the function further needs the
/// index (if any) and the information whether the index is supposed to be embedded.
/// An error is returend if the index must be embedded but no index is provided.
///
/// * `number` - The finite field element.
/// * `index` - The index of the finite field element.
/// * `embed_index` - Flag indicating whether the index is to be embedded.
/// * `word_list` - The word list.
pub(crate) fn get_seed_phrase_for_element_with_embedding(
    element: &FiniteFieldElement,
    index: Option<u32>,
    embed_index: bool,
    word_list: &[&str],
) -> SeedPhraseResult {
    // Ensure that there is an index if it is to be embedded.
    if embed_index && index.is_none() {
        return Err(HarpoError::InvalidParameter(
            "No index is provided to embed in the seed phrase.".into(),
        ));
    }
    // Get the bytes.
    let bytes = element.get_bytes();
    // Compute the SHA-256 hash.
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    // Create the bytes with bits of the hash appended.
    let num_words = ((bytes.len() << 3) + NUM_BITS_PER_WORD - 1) / NUM_BITS_PER_WORD;
    let total_num_bits = num_words * NUM_BITS_PER_WORD;
    // Prepare the byte array for the words.
    let mut encoded_words = vec![0; (total_num_bits + 7) >> 3];
    // Copy the number into the encoded words array.
    encoded_words[..bytes.len()].clone_from_slice(&bytes[..]);
    // When embedding the index of the seed phrase, it is placed in the 4 higher-order bits
    // of the byte that holds the first byte of the hash.
    // Since the index is at least 1, we subtract 1 so that we can use one more index.
    encoded_words[bytes.len()] = if embed_index {
        match index {
            Some(embedded_index) => (((embedded_index - 1) as u8) << 4) + (hash[0] % (1 << 4)),
            None => hash[0],
        }
    } else {
        hash[0]
    };
    // Retrieve the indices from the given byte array.
    let indices = get_indices_from_bytes(&encoded_words, num_words)?;
    // Turn the indices into words.
    let words: Vec<String> = indices
        .iter()
        .map(|index| word_list[*index].to_string())
        .collect();
    // Return the seed phrase.
    if !embed_index {
        // If the index is not embedded but there is an index, it must be provided explicitly.
        match index {
            Some(embedded_index) => Ok(SeedPhrase::new_with_index(&words, embedded_index)),
            None => Ok(SeedPhrase::new(&words)),
        }
    } else {
        Ok(SeedPhrase::new(&words))
    }
}

/// The function returns the indices encoded in the given byte array.
///
/// The indices of the words are retrieved based on the BIP-0039 specification.
///
/// * `bytes` - The given byte array
/// * `num_words` - The number of encoded words.
fn get_indices_from_bytes(bytes: &[u8], num_words: usize) -> HarpoResult<Vec<usize>> {
    let mut current_index: usize = 0;
    let mut read_bits = 0;
    let mut indices = vec![];
    // Process every byte.
    for byte in bytes {
        // If `NUM_BITS_PER_WORD` bits are read including the current byte, a new word index
        // is computed.
        if read_bits + 8 >= NUM_BITS_PER_WORD {
            // Keep track of the number of processed bits.
            let processed_bits = NUM_BITS_PER_WORD - read_bits;
            // The remaining bits are used for the next index.
            let remaining_bits = 8 - processed_bits;
            // Remove the remaining bits to get the processed part.
            let processed_part = (*byte as usize) >> remaining_bits;
            // The current index is finalized by appending the processed part.
            current_index = (current_index << processed_bits) + processed_part;
            // Add the index.
            indices.push(current_index);
            // Update the current index with the remaining bits.
            current_index = (*byte as usize) % (1 << remaining_bits);
            // The number of read bits is the number of remaining bits.
            read_bits = remaining_bits;
        } else {
            // The whole byte is appended to the current index.
            current_index = (current_index << 8) + (*byte as usize);
            // The number of read bytes increases by 8.
            read_bits += 8;
        }
        // Once we have read the desired number of words, return them.
        if indices.len() == num_words {
            return Ok(indices);
        }
    }
    Err(HarpoError::InvalidSeedPhrase(
        "Error parsing indices from byte array.".to_string(),
    ))
}

// ******************************** TESTS ********************************

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_sharing::get_modulus_for_bits;
    use rand::{seq::SliceRandom, Rng};
    use std::error::Error;

    /// The number of valid key sizes is 5 (128, 160, 192, 224, 256).
    const NUM_VALID_KEY_SIZES: usize = 5;
    /// The number of test runs.
    const NUM_TEST_RUNS: usize = 1000;

    /// The function converts a Hex string into a series of bytes.
    ///
    /// * `input` - The input in the form of a Hex string.
    fn decode_hex_bytes(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        if input.len() % 2 != 0 {
            Err("Error decoding hex string: The input length is not a multiple of 2.".into())
        } else {
            (0..input.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|e| e.into()))
                .collect()
        }
    }

    #[test]
    /// A simple test function that tests the conversion from
    ///      107      139       93      210      150       45
    /// to
    ///      107      139       93      210      150       45 =
    /// 01101011 10001011 01011101 11010010 10010110 00101101 =
    /// 01101011100 01011010111 01110100101 00101100010       =
    ///         860         727         933         354
    ///
    /// and from
    ///
    ///      229       26      179      110      211       38      214
    /// to
    ///      229       26      179      110      211       38      214 =
    /// 11100101 00011010 10110011 01101110 11010011 00100110 11010110 =
    /// 11100101000 11010101100 11011011101 10100110010 01101101011    =
    ///        1832        1708        1757        1330         875
    fn test_indices_from_bytes() {
        // A test with 4 words.
        let num_words = 4;
        let bytes: &[u8] = &[107, 139, 93, 210, 150, 45];
        let indices = get_indices_from_bytes(bytes, num_words).unwrap();
        let expected_indices: Vec<usize> = vec![860, 727, 933, 354];
        assert_eq!(indices, expected_indices);
        // A test with 5 words.
        let num_words = 5;
        let bytes: &[u8] = &[229, 26, 179, 110, 211, 38, 214];
        let indices = get_indices_from_bytes(bytes, num_words).unwrap();
        let expected_indices: Vec<usize> = vec![1832, 1708, 1757, 1330, 875];
        assert_eq!(indices, expected_indices);
    }

    /// This function tests the conversion from a byte array to a seed phrase
    /// and vice versa.
    ///
    /// * `hex_number` - The input number as a Hex string.
    /// * `phrase` - The corresponding seed phrase.
    fn test_seed_phrase_conversion_vector(hex_number: &str, phrase: &str) {
        // Obtain the bytes from the hexadecimal encoding.
        let value = decode_hex_bytes(hex_number).unwrap();
        // Get the modulus from the size of the byte array.
        let modulus = get_modulus_for_bits(value.len() << 3).unwrap();
        // Create the corresponding finite field element.
        let element = FiniteFieldElement::new(&value, &modulus);
        // Get the seed phrase for the element.
        let seed_phrase = get_seed_phrase_for_element(&element, &DEFAULT_WORD_LIST).unwrap();
        let target_list: Vec<&str> = phrase.split(' ').collect();
        // Assert that the word list corresponds to the list in the test vector.
        assert_eq!(seed_phrase.get_words(), target_list);
        // Get the element for the seed phrase derived from the target list.
        let target_string_list: Vec<String> =
            target_list.iter().map(|slice| slice.to_string()).collect();
        let derived_seed_phrase = SeedPhrase::new(&target_string_list);
        let derived_element =
            get_element_for_seed_phrase(&derived_seed_phrase, &DEFAULT_WORD_LIST).unwrap();
        // Assert that the derived element equals the decoded element.
        assert_eq!(derived_element, element);
    }

    #[test]
    // This function generates random seed phrases and tests the correct conversion.
    fn test_random_seed_phrase_conversion() {
        // The valid key sizes in bytes.
        let key_sizes: [usize; NUM_VALID_KEY_SIZES] = [16, 20, 24, 28, 32];
        let mut rng = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            // Generate a random key.
            let random_bytes = rng.gen::<[u8; 32]>();
            let size = key_sizes.choose(&mut rng).unwrap();
            let mut random_key: Vec<u8> = vec![0; *size];
            random_key.clone_from_slice(&random_bytes[..*size]);
            // Generate the corresponding finite field element.
            let modulus = get_modulus_for_bits(size << 3).unwrap();
            let element = FiniteFieldElement::new(&random_key, &modulus);
            // Generate the seed phrase.
            let seed_phrase = get_seed_phrase_for_element(&element, &DEFAULT_WORD_LIST).unwrap();
            // Derive the element from the seed phrase.
            let derived_element =
                get_element_for_seed_phrase(&seed_phrase, &DEFAULT_WORD_LIST).unwrap();
            // Assert that the derived element equals the original element.
            assert_eq!(element, derived_element);
        }
    }

    #[test]
    // This function tests the random seed phrase generation.
    fn test_random_seed_phrase_generation() {
        // The valid number of words.
        let valid_num_words: [usize; NUM_VALID_KEY_SIZES] = [12, 15, 18, 21, 24];
        let mut rng = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            // Generate a random seed phrase.
            let num_words = valid_num_words
                .choose(&mut rng)
                .expect("A valid random number of words should be chosen.");
            let seed_phrase = get_random_seed_phrase(*num_words, &DEFAULT_WORD_LIST)
                .expect("A valid seed phrase should be generated.");
            // Make sure that the number of words is correct.
            assert_eq!(seed_phrase.len(), *num_words);
            // Make sure it is BIP-0039 compliant.
            assert!(is_compliant(&seed_phrase, &DEFAULT_WORD_LIST));
        }
    }

    /// Macro rules for the seed phrase conversion tests.
    macro_rules! tests {
        ($([$hex_number:expr, $phrase:expr]),*) => {
            #[test]
            fn test_seed_phrase_conversion() {
                $(
                    test_seed_phrase_conversion_vector($hex_number, $phrase);
                )*
            }
        };
    }

    tests! {
        // The mnemonic test vectors have been copied from this URL:
        // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        [
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ],
        [
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        ],
        [
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        ],
        [
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        ],
        [
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
        ],
        [
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
        ],
        [
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"
        ],
        [
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ],
        [
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
        ],
        [
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
        ],
        [
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        ],
        [
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
        ],
        [
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"
        ],
        [
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
        ],
        [
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow"
        ],
        [
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"
        ],
        [
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"
        ],
        [
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train"
        ],
        [
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access"
        ],
        [
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"
        ],
        [
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        ],
        [
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump"
        ],
        [
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
        ]
    }
}
