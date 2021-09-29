use crate::math::FiniteFieldElement;
use crate::secret_sharing::get_modulus_for_words;
use sha2::{Digest, Sha256};
use std::cmp;
use std::error::Error;
use std::fmt;

const NUM_VALID_KEY_SIZES: usize = 5;
const NUM_BITS_PER_WORD: usize = 11;
const NUM_BITS_PER_INDEX: usize = 4;
const ENTROPY_INCREMENT: usize = 32;

const NUM_TEST_RUNS: usize = 1000;

#[derive(Eq)]
pub struct MnemonicCode {
    words: Vec<String>,
    index: Option<u32>,
}

impl MnemonicCode {
    pub fn new(words: &[String]) -> Self {
        let internal_words: Vec<String> = words.to_vec();
        MnemonicCode {
            words: internal_words,
            index: None,
        }
    }

    pub fn new_with_index(words: &[String], index: u32) -> Self {
        let internal_words: Vec<String> = words.to_vec();
        MnemonicCode {
            words: internal_words,
            index: Some(index),
        }
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.len() == 0
    }

    pub fn get_words(&self) -> Vec<&str> {
        self.words.iter().map(|s| s.as_str()).collect()
    }

    pub fn get_index(&self) -> Option<u32> {
        self.index
    }

    pub fn get_num_bits(&self) -> usize {
        // The number of security bits is the total number of bits rounded down to the
        // nearest multiple of 'ENTROPY_INCREMENT'.
        ((self.words.len() * NUM_BITS_PER_WORD) / ENTROPY_INCREMENT) * ENTROPY_INCREMENT
    }
}

impl fmt::Display for MnemonicCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut words_with_spaces = String::new();
        for index in 0..(self.words.len() - 1) {
            words_with_spaces.push_str(&self.words[index]);
            words_with_spaces.push(' ');
        }
        words_with_spaces.push_str(&self.words[self.words.len() - 1]);
        match self.index {
            Some(index) => write!(f, "{}: {}", index, words_with_spaces),
            None => write!(f, "{}", words_with_spaces),
        }
    }
}

impl PartialEq for MnemonicCode {
    fn eq(&self, other: &Self) -> bool {
        self.words == other.words
    }
}

fn get_index(word: &str, word_list: &[&str]) -> Option<usize> {
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
    None
}

pub(crate) fn get_element_for_mnemonic_code(
    mnemonic_code: &MnemonicCode,
    word_list: &[&str],
) -> Result<FiniteFieldElement, Box<dyn Error>> {
    // Get the element and discard the index.
    let (element, _) = get_element_and_index_for_mnemonic_code(mnemonic_code, word_list)?;
    // Return the corresponding finite field element.
    Ok(element)
}

pub(crate) fn get_element_and_index_for_mnemonic_code(
    mnemonic_code: &MnemonicCode,
    word_list: &[&str],
) -> Result<(FiniteFieldElement, u32), Box<dyn Error>> {
    let num_words = mnemonic_code.len();
    if num_words % 3 != 0 || num_words < 12 || num_words > 24 {
        return Err("The number of words must be 12, 15, 18, 21, or 24.".into());
    }
    // The words are mapped to their indices in the word list:
    let index_list: Vec<usize> = mnemonic_code
        .get_words()
        .iter()
        .map(|word| {
            get_index(word, word_list).expect("A word is used that is not in the word list.")
        })
        .collect();
    // Convert the indices into a byte array.
    let bytes = get_bytes_from_indices(&index_list);
    // The number of bytes used to build the element is a multiple of 32 bit = 4 bytes.
    let num_used_bytes = (bytes.len() >> 2) << 2;
    // Copy the bytes into a new array.
    let mut used_bytes: Vec<u8> = vec![0; num_used_bytes];
    used_bytes.clone_from_slice(&bytes[0..num_used_bytes]);
    // Get the modulus. Calling unwrap() is okay here
    // because the number of words is checked at the beginning of the function call.
    let modulus = get_modulus_for_words(num_words).unwrap();
    // Get the index.
    let index = if let Some(index) = mnemonic_code.get_index() {
        index
    } else {
        // The index is encoded in the byte at index `num_used_bytes`.
        (bytes[num_used_bytes] >> (8 - NUM_BITS_PER_INDEX)) as u32
    };
    // Return the corresponding finite field element and index.
    Ok((FiniteFieldElement::new(&bytes, &modulus), index))
}

fn get_bytes_from_indices(indices: &[usize]) -> Vec<u8> {
    // Round the number of bytes up so that there is space for all indices.
    let size = (indices.len() * NUM_BITS_PER_WORD + 7) / 8;
    // Thhe bytes are written into this byte array.
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
            // If the index fits into two bytes, consuming all bits of the second byte,
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

pub(crate) fn get_mnemonic_code_for_element(
    number: &FiniteFieldElement,
    index: Option<u32>,
    embed_index: bool,
    word_list: &[&str],
) -> Result<MnemonicCode, Box<dyn Error>> {
    // Ensure that there is an index if it is to be embedded.
    if embed_index && index.is_none() {
        return Err("Error no index is provided to embed in the mnemonic code.".into());
    }
    // Get the bytes.
    let bytes = number.get_bytes();
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
    // When embedding the index of the mnemonic code, it is placed in the 4 higher-order bits
    // of the byte that holds the first byte of the hash.
    encoded_words[bytes.len()] = if embed_index {
        match index {
            Some(embedded_index) => ((embedded_index as u8) << 4) + (hash[0] % (1 << 4)),
            None => hash[0],
        }
    }else {
        hash[0]
    };
    // Retrieve the indices from the given byte array.
    let indices = get_indices_from_bytes(&encoded_words, num_words)?;
    // Turn the indices into words.
    let words: Vec<String> = indices
        .iter()
        .map(|index| word_list[*index].to_string())
        .collect();
    // Return the mnemonic code.
    if !embed_index {
        // If the index is not embedded but there is an index, we need to provide it explicitly.
        match index {
            Some(embedded_index) => Ok(MnemonicCode::new_with_index(&words, embedded_index)),
            None => Ok(MnemonicCode::new(&words))
        }
    }else {
        Ok(MnemonicCode::new(&words))
    }
}

fn get_indices_from_bytes(bytes: &[u8], num_words: usize) -> Result<Vec<usize>, Box<dyn Error>> {
    let mut current_index: usize = 0;
    let mut read_bits = 0;
    let mut indices = vec![];
    for byte in bytes {
        if read_bits + 8 >= NUM_BITS_PER_WORD {
            let processed_bits = NUM_BITS_PER_WORD - read_bits;
            let remaining_bits = 8 - processed_bits;
            let processed_part = (*byte as usize) >> remaining_bits;
            current_index = (current_index << processed_bits) + processed_part;
            indices.push(current_index);
            let mask = (1 << remaining_bits) - 1;
            current_index = (*byte as usize) & mask;
            read_bits = remaining_bits;
        } else {
            current_index = (current_index << 8) + (*byte as usize);
            read_bits += 8;
        }
        if indices.len() == num_words {
            return Ok(indices);
        }
    }
    Err("Error parsing indices from byte array.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_sharing::get_modulus_for_bits;
    use crate::word_list::DEFAULT_WORD_LIST;
    use rand::{seq::SliceRandom, Rng};

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
    /// 01101011 10001011 01011101 11010010 10010110 00101101
    /// 01101011100 01011010111 01110100101 00101100010
    /// 860 727 933 354

    /// 11100101 00011010 10110011 01101110 11010011 00100110 11010110
    /// 11100101000 11010101100 11011011101 10100110010 01101101011
    /// 1832 1708 1757 1330 875
    fn test_indices_from_bytes() {
        let num_words = 4;
        let bytes: &[u8] = &[107, 139, 93, 210, 150, 45];
        let indices = get_indices_from_bytes(bytes, num_words).unwrap();
        let expected_indices: Vec<usize> = vec![860, 727, 933, 354];
        assert_eq!(indices, expected_indices);

        let num_words = 5;
        let bytes: &[u8] = &[229, 26, 179, 110, 211, 38, 214];
        let indices = get_indices_from_bytes(bytes, num_words).unwrap();
        let expected_indices: Vec<usize> = vec![1832, 1708, 1757, 1330, 875];
        assert_eq!(indices, expected_indices);
    }

    /// This function tests the conversion from a byte array to a mnemonic code
    /// and vice versa.
    fn test_mnemonic_code_conversion_vector(hex_number: &str, phrase: &str) {
        // Obtain the bytes from the hexadecimal encoding.
        let value = decode_hex_bytes(hex_number).unwrap();
        // Get the modulus from the size of the byte array.
        let modulus = get_modulus_for_bits(value.len() << 3).unwrap();
        // Create the corresponding finite field element.
        let element = FiniteFieldElement::new(&value, &modulus);
        // Get the mnemonic code for the element.
        let mnemonic_code = get_mnemonic_code_for_element(&element, 0, &DEFAULT_WORD_LIST).unwrap();
        let target_list: Vec<&str> = phrase.split(' ').collect();
        // Assert that the word list corresponds to the list in the test vector.
        assert_eq!(mnemonic_code.get_words(), target_list);
        // Get the element for the mnemonic code derived from the target list.
        let target_string_list: Vec<String> =
            target_list.iter().map(|slice| slice.to_string()).collect();
        let derived_mnemonic_code = MnemonicCode::new(&target_string_list);
        let derived_element =
            get_element_for_mnemonic_code(&derived_mnemonic_code, &DEFAULT_WORD_LIST)
                .unwrap();
        // Assert that the derived element equals the decoded element.
        assert_eq!(derived_element, element);
    }

    #[test]
    // This function generates random mnemonic codes and tests the correct conversion.
    fn test_random_mnemonic_code_conversion() {
        // The valid key sizes in bytes.
        let key_sizes: [usize; NUM_VALID_KEY_SIZES] = [16, 20, 24, 28, 32];
        let mut rand = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            // Generate a random key.
            let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
            let size = key_sizes.choose(&mut rand).unwrap();
            let mut random_key: Vec<u8> = vec![0; *size];
            random_key.clone_from_slice(&random_bytes[..*size]);
            // Generate the corresponding finite field element.
            let modulus = get_modulus_for_bits(size << 3).unwrap();
            let element = FiniteFieldElement::new(&random_key, &modulus);
            // Generate the mnemonic code.
            let mnemonic = get_mnemonic_code_for_element(&element, 0, &DEFAULT_WORD_LIST).unwrap();
            // Derive the element from the mnemonic code.
            let derived_element =
                get_element_for_mnemonic_code(&mnemonic, &DEFAULT_WORD_LIST).unwrap();
            // Assert that the derived element equals the original element.
            assert_eq!(element, derived_element);
        }
    }

    macro_rules! tests {
        ($([$hex_number:expr, $phrase:expr]),*) => {
            #[test]
            fn test_mnemonic_code_conversion() {
                $(
                    test_mnemonic_code_conversion_vector($hex_number, $phrase);
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
