use crate::math::FiniteFieldElement;
use num_bigint::BigUint;
use std::fmt;

/// For each modulus, the largest prime number is used for each bit length.
/// These prime numbers can be found here: https://primes.utm.edu/lists/2small/200bit.html

/// The prime number
/// 2^128-159 = 340282366920938463463374607431768211297
/// is used for 128-bit inputs.
pub const MODULUS_ARRAY_128: [u32; 4] = [u32::MAX - 158, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^160-47 = 1461501637330902918203684832716283019655932542929
/// is used for 160-bit inputs.
pub const MODULUS_ARRAY_160: [u32; 5] = [u32::MAX - 46, u32::MAX, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^192-237 = 6277101735386680763835789423207666416102355444464034512659
/// is used for 192-bit inputs.
pub const MODULUS_ARRAY_192: [u32; 6] = [
    u32::MAX - 236,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
];

/// The prime number
/// 2^224-63 = 26959946667150639794667015087019630673637144422540572481103610249153
/// is used for 224-bit inputs.
pub const MODULUS_ARRAY_224: [u32; 7] = [
    u32::MAX - 62,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
];

/// The prime number
/// 2^256-189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747
/// is used for 256-bit inputs.
pub const MODULUS_ARRAY_256: [u32; 8] = [
    u32::MAX - 188,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
    u32::MAX,
];

pub(crate) fn get_modulus_for_bits(num_bits: usize) -> Option<BigUint> {
    match num_bits {
        128 => Some(BigUint::from_slice(&MODULUS_ARRAY_128)),
        160 => Some(BigUint::from_slice(&MODULUS_ARRAY_160)),
        192 => Some(BigUint::from_slice(&MODULUS_ARRAY_192)),
        224 => Some(BigUint::from_slice(&MODULUS_ARRAY_224)),
        256 => Some(BigUint::from_slice(&MODULUS_ARRAY_256)),
        _ => None,
    }
}

pub(crate) fn get_modulus_for_words(num_words: usize) -> Option<BigUint> {
    match num_words {
        12 => Some(BigUint::from_slice(&MODULUS_ARRAY_128)),
        15 => Some(BigUint::from_slice(&MODULUS_ARRAY_160)),
        18 => Some(BigUint::from_slice(&MODULUS_ARRAY_192)),
        21 => Some(BigUint::from_slice(&MODULUS_ARRAY_224)),
        24 => Some(BigUint::from_slice(&MODULUS_ARRAY_256)),
        _ => None,
    }
}

pub(crate) struct SecretPolynomial {
    coefficients: Vec<FiniteFieldElement>,
}

pub(crate) struct SecretShare {
    pub index: u32,
    pub element: FiniteFieldElement,
}

impl fmt::Display for SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.index, self.element.value)
    }
}

impl SecretPolynomial {
    pub(crate) fn new(secret: &FiniteFieldElement, num_bits: usize, degree: usize) -> Option<Self> {
        let modulus_option = get_modulus_for_bits(num_bits);
        match modulus_option {
            Some(modulus) => {
                let mut coefficients = vec![secret.clone()];
                for _in in 1..=degree {
                    coefficients.push(FiniteFieldElement::new_random(num_bits, &modulus));
                }
                Some(SecretPolynomial { coefficients })
            }
            None => None,
        }
    }

    fn evaluate(&self, value: u32) -> FiniteFieldElement {
        let degree = self.coefficients.len() - 1;
        let mut result = self.coefficients[degree].clone();
        let finite_field_value = FiniteFieldElement::new_integer(value, &result.modulus);
        for index in (0..degree).rev() {
            result = (result * finite_field_value.clone()) + self.coefficients[index].clone();
        }
        result
    }

    pub(crate) fn get_secret_shares(&self, number: u32) -> Vec<SecretShare> {
        // The shares correspond to the polynomial points
        // `f(1), f(2), ..., f(number)`.
        let mut secret_shares = vec![];
        for index in 1..=number {
            secret_shares.push(SecretShare {
                index,
                element: self.evaluate(index),
            });
        }
        secret_shares
    }
}

pub(crate) fn reconstruct_secret(secret_shares: &[SecretShare]) -> FiniteFieldElement {
    // Get the modulus from the finite field element of the first share:
    let modulus = &secret_shares[0].element.modulus;
    // Create the list of indices:
    let indices: Vec<u32> = secret_shares.iter().map(|share| share.index).collect();
    let mut secret = FiniteFieldElement::new_integer(0, modulus);
    // Process each share:
    for secret_share in secret_shares {
        let term = secret_share.element.clone();
        let mut multiply_term = FiniteFieldElement::new_integer(1, modulus);
        let mut divide_term = FiniteFieldElement::new_integer(1, modulus);
        let other_indices: Vec<u32> = indices
            .iter()
            .copied()
            .filter(|index| *index != secret_share.index)
            .collect();
        for index in other_indices {
            let index_element = FiniteFieldElement::new_integer(index, modulus);
            let secret_share_index_element =
                FiniteFieldElement::new_integer(secret_share.index, modulus);
            multiply_term = multiply_term * index_element.clone();
            divide_term = divide_term * (index_element - secret_share_index_element.clone());
        }
        // Update the secret:
        secret = secret + (term * multiply_term / divide_term);
    }
    secret
}

// ******************************** TESTS ********************************

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;

    #[test]
    /// The function tests the evaluation of a secret polynomial:
    fn test_polynomial_evaluation() {
        let modulus = get_modulus_for_bits(128).unwrap();
        let secret = FiniteFieldElement::new_random(128, &modulus);
        let polynomial = SecretPolynomial::new(&secret, 128, 2).unwrap();
        // Evaluate the secret polynomial at 0:
        assert_eq!(polynomial.evaluate(0), secret);
        // Evaluate the secret polynomial at 1 (which should be the sum of coefficients):
        let mut coefficient_sum: FiniteFieldElement = FiniteFieldElement::new_integer(0, &modulus);
        for coefficient in &polynomial.coefficients {
            coefficient_sum = coefficient_sum + coefficient.clone();
        }
        assert_eq!(polynomial.evaluate(1), coefficient_sum);
    }

    #[test]
    /// The function tests the reconstruction of the secret parameter in the polynomial.
    fn test_working_secret_reconstruction() {
        let secret = FiniteFieldElement::new_random(256, &get_modulus_for_bits(256).unwrap());
        let polynomial = SecretPolynomial::new(&secret, 256, 2).unwrap();
        let shares = polynomial.get_secret_shares(5);
        let indices: Vec<u32> = (1..5).collect();
        let random_shares: Vec<u32> = indices
            .choose_multiple(&mut rand::thread_rng(), 3)
            .copied()
            .collect();
        let random_shares: Vec<SecretShare> = shares
            .into_iter()
            .filter(|share| random_shares.contains(&share.index))
            .collect();
        let reconstructed_secret = reconstruct_secret(&random_shares);
        assert_eq!(secret, reconstructed_secret);
    }

    #[test]
    /// The function enssures that secret cannot be reconstructed when fewer than `degree+1`
    // shares are combined.
    fn test_failing_secret_reconstruction() {
        let modulus = &get_modulus_for_bits(256).unwrap();
        let secret = FiniteFieldElement::new_random(256, modulus);
        let polynomial = SecretPolynomial::new(&secret, 256, 2).unwrap();
        let shares = polynomial.get_secret_shares(5);
        let indices: Vec<u32> = (1..5).collect();
        let random_shares: Vec<u32> = indices
            .choose_multiple(&mut rand::thread_rng(), 2)
            .copied()
            .collect();
        let random_shares: Vec<SecretShare> = shares
            .into_iter()
            .filter(|share| random_shares.contains(&share.index))
            .collect();
        let reconstructed_secret = reconstruct_secret(&random_shares);
        assert_ne!(secret, reconstructed_secret);
    }
}
