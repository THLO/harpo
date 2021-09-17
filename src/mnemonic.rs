use crate::math::FiniteFieldElement;
use crate::secret_sharing::{
    MODULUS_ARRAY_128, MODULUS_ARRAY_160, MODULUS_ARRAY_192, MODULUS_ARRAY_224, MODULUS_ARRAY_256,
};
use num_bigint::BigUint;
use num_traits::Zero;
use std::error::Error;

const NUM_BITS_PER_WORD: usize = 11;
const ENTROPY_INCREMENT: usize = 32;

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if input.len() % 2 != 0 {
        Err("Error decoding hex string: The input length is odd".into())
    } else {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|e| e.into()))
            .collect()
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

fn encode_phrase(words: &[&str], word_list: &[&str]) -> Result<FiniteFieldElement, Box<dyn Error>> {
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
    let num_ignored_bits = num_words * NUM_BITS_PER_WORD % ENTROPY_INCREMENT;
    // The number of used bits:
    let num_used_bits = NUM_BITS_PER_WORD - num_ignored_bits;
    // The mask that is applied to the last index:
    let mask = (1 << num_used_bits) - 1;
    // Apply the mask to the last index:
    index_list[num_words - 1] &= mask;
    // Compose the finite field element:
    let mut number = Zero::zero();
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
    Ok(FiniteFieldElement::new(&number, &modulus))
}

fn test_hex_number_passphrase(hex_number: &str, phrase: &str) {
    let _bytes = decode_hex(hex_number).unwrap();
}

macro_rules! tests {
    ($([$hex_number:expr, $phrase:expr]),*) => {
        #[test]
        fn test_mnemonics() {
            $(
                test_hex_number_passphrase($hex_number, $phrase);
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
