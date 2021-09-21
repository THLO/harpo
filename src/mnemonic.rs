use crate::math::FiniteFieldElement;
use crate::secret_sharing::{
    MODULUS_ARRAY_128, MODULUS_ARRAY_160, MODULUS_ARRAY_192, MODULUS_ARRAY_224, MODULUS_ARRAY_256,
};
use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};
use std::error::Error;

const NUM_BITS_PER_WORD: usize = 11;
const ENTROPY_INCREMENT: usize = 32;

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

fn get_number_for_seed_phrase(
    words: &[&str],
    word_list: &[&str],
) -> Result<FiniteFieldElement, Box<dyn Error>> {
    let num_words = words.len();
    if num_words % 3 != 0 || num_words < 12 || num_words > 24 {
        return Err("The number of words must be 12, 15, 18, 21, or 24.".into());
    }
    // The words are mapped to their indices in the word list:
    let mut index_list: Vec<usize> = words
        .iter()
        .map(|word| {
            get_index(word, word_list).expect("A word is used that is not in the word list.")
        })
        .collect();
    // The number of bits that are ignored:
    let num_ignored_bits = (num_words * NUM_BITS_PER_WORD) % ENTROPY_INCREMENT;
    // The number of used bits:
    let num_used_bits = NUM_BITS_PER_WORD - num_ignored_bits;
    // The mask that is applied to the last index:
    let mask = (1 << num_used_bits) - 1;
    // Apply the mask to the last index:
    index_list[num_words - 1] &= mask;
    // Compose the finite field element:
    let mut number: BigUint = Zero::zero();
    for index in (0..num_words).rev() {
        number = (number << NUM_BITS_PER_WORD) + index_list[index];
    }
    // Get the modulus.
    let modulus = match num_used_bits {
        128 => BigUint::from_slice(&MODULUS_ARRAY_128),
        160 => BigUint::from_slice(&MODULUS_ARRAY_160),
        192 => BigUint::from_slice(&MODULUS_ARRAY_192),
        224 => BigUint::from_slice(&MODULUS_ARRAY_224),
        256 => BigUint::from_slice(&MODULUS_ARRAY_256),
        _ => return Err("Invalid number of bits of security.".into()),
    };
    // Return the corresponding finite field element.
    Ok(FiniteFieldElement::new(&number.to_bytes_le(), &modulus))
}

fn get_seed_phrase_for_number(
    number: &FiniteFieldElement,
    word_list: &[&str],
) -> Result<Vec<String>, Box<dyn Error>> {
    // Get the bytes.
    let mut bytes = number.get_bytes();
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
    // Append a single byte of the hash. This is sufficient as the checksum length is
    // at most 8 bits.
    encoded_words[bytes.len()] = hash[0];
    // Retrieve the indices from the given byte array.
    let indices = get_indices_from_bytes(&encoded_words, num_words)?;
    // Turn the indices into words.
    let words: Vec<String> = indices
        .iter()
        .map(|index| word_list[*index].to_string())
        .collect();
    // Return the words.
    Ok(words)
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
    use crate::word_list::DEFAULT_WORD_LIST;

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

    fn test_seed_phrase_from_number(hex_number: &str, phrase: &str) {
        let mut value = decode_hex_bytes(hex_number).unwrap();
        let modulus = match value.len() {
            16 => BigUint::from_slice(&MODULUS_ARRAY_128),
            20 => BigUint::from_slice(&MODULUS_ARRAY_160),
            24 => BigUint::from_slice(&MODULUS_ARRAY_192),
            28 => BigUint::from_slice(&MODULUS_ARRAY_224),
            32 => BigUint::from_slice(&MODULUS_ARRAY_256),
            len => panic!("Invalid bit length in test: {}", len << 3),
        };
        let element = FiniteFieldElement::new(&value, &modulus);
        let word_list = get_seed_phrase_for_number(&element, &DEFAULT_WORD_LIST).unwrap();
        let target_list: Vec<_> = phrase.split(' ').collect();
        assert_eq!(word_list, target_list);
    }

    macro_rules! tests {
        ($([$hex_number:expr, $phrase:expr]),*) => {
            #[test]
            fn test_mnemonics() {
                $(
                    test_seed_phrase_from_number($hex_number, $phrase);
                )*
            }
        };
    }

    tests! {
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
