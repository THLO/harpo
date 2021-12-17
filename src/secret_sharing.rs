//! The `secret_sharing` module provides the functionality to create secret shares for a
//! secret finite field element and reconstruct the secret element given sufficiently many
//! secret shares.
//!
//! For each supported bit length, the used modulus is defined as the largest prime number with the
//! given number of bits.
//! These prime numbers can be found here: <https://primes.utm.edu/lists/2small/200bit.html>

use crate::math::FiniteFieldElement;
use num_bigint::BigUint;
use std::fmt;

/// The prime number
/// 2^128-159 = 340282366920938463463374607431768211297
/// is used as the modulus for 128-bit inputs.
pub const MODULUS_ARRAY_128: [u32; 4] = [u32::MAX - 158, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^160-47 = 1461501637330902918203684832716283019655932542929
/// is used as the modulus for 160-bit inputs.
pub const MODULUS_ARRAY_160: [u32; 5] = [u32::MAX - 46, u32::MAX, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^192-237 = 6277101735386680763835789423207666416102355444464034512659
/// is used as the modulus for 192-bit inputs.
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
/// is used as the modulus for 224-bit inputs.
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
/// is used as the modulus for 256-bit inputs.
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

/// The function returns the modulus for the given security level.
///
/// * `num_bits`: The security level (128, 160, 192, 224, or 256).
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

/// The function returns the modulus for the given number of words.
///
/// The number of words correlates with the security level, starting with 12 words
/// for 128-bit security up to 24 words for 256-bit security.
/// * `num_words`: The number of words (12, 15, 18, 21, or 24).
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

/// The struct used to represent polynomials encapsulating a secret.
pub(crate) struct SecretPolynomial {
    /// The vector of coefficients.
    coefficients: Vec<FiniteFieldElement>,
}

/// The struct used to represent a secret share.
pub(crate) struct SecretShare {
    /// The index of the secret share.
    pub index: u32,
    /// The value of the secret share, which is obtained by evaluating the underlying
    /// polynomial at `index`.
    pub element: FiniteFieldElement,
}

impl SecretShare {
    /// The function creates a secret share based on the provided finite field element and index.
    ///
    /// * `element` - The finite field element.
    /// * `index` - The index.
    pub fn new(element: &FiniteFieldElement, index: u32) -> Self {
        SecretShare {
            index,
            element: element.clone(),
        }
    }
}

impl Clone for SecretShare {
    /// The function defines how a secret share is cloned.
    fn clone(&self) -> SecretShare {
        SecretShare {
            index: self.index,
            element: self.element.clone(),
        }
    }
}

impl fmt::Display for SecretShare {
    /// The function defines how a secret share is printed.
    ///
    /// A secret share is printed in brackets containing the index and the finite field element
    /// separated by a comma.
    ///
    /// * `formatter` - The formatter.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}, {}]", self.index, self.element.value)
    }
}

impl SecretPolynomial {
    /// The function creates a random polynomial that embeds the provided secret.
    ///
    /// The function uses the provided secret as the constant coefficient and creates all other
    /// coefficients randomly.
    /// A polynomial is only returned if there is a modulus defined for the given number of bits.
    ///
    /// * `secret` - The secret embedded in the polynomial.
    /// * `num_bits` - The security level in bits.
    ///  * `degree` - The degree of the constructed polynomial.
    pub(crate) fn new(secret: &FiniteFieldElement, num_bits: usize, degree: usize) -> Option<Self> {
        match get_modulus_for_bits(num_bits) {
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

    /// The function evaluates the polynomial at the given value.
    ///
    /// * `value` - The value for which the polynomial is evaluated.
    fn evaluate(&self, value: u32) -> FiniteFieldElement {
        let degree = self.coefficients.len() - 1;
        let mut result = self.coefficients[degree].clone();
        // Convert the value to a finite field element.
        let finite_field_value = FiniteFieldElement::new_integer(value, &result.modulus);
        // Iterate over the coefficients in reverse order.
        for index in (0..degree).rev() {
            result = (result * finite_field_value.clone()) + self.coefficients[index].clone();
        }
        result
    }

    /// The function returns the requested number of secret shares.
    ///
    /// * `number` - The number of requested secret shares.
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

/// The function reconstructs the secret based on the provided secret shares.
///
/// The function assumes that the degree of the polynomial is one less than the number of
/// provided secret shares. If any secret share is wrong or an insufficient number of
/// secret shares is provided, the function will essentially return a random value.
///
/// * `secret_shares` - The provided secret shares.
pub(crate) fn reconstruct_secret(secret_shares: &[SecretShare]) -> FiniteFieldElement {
    // Get the modulus from the finite field element of the first share.
    let modulus = &secret_shares[0].element.modulus;
    // Create the list of indices.
    let indices: Vec<u32> = secret_shares.iter().map(|share| share.index).collect();
    let mut secret = FiniteFieldElement::new_integer(0, modulus);
    // Process each share.
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
    use rand::{seq::SliceRandom, Rng};

    /// The number of test runs.
    const NUM_TEST_RUNS: usize = 10;

    #[test]
    /// The function tests the evaluation of a random secret embedded in a secret polynomial
    /// at value 0 (extracting the secret) and 1 (returning the sum of the coefficients).
    fn test_polynomial_evaluation() {
        let modulus = get_modulus_for_bits(128).unwrap();
        let mut rng = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            let secret = FiniteFieldElement::new_random(128, &modulus);
            let degree = rng.gen_range(2..20);
            let polynomial = SecretPolynomial::new(&secret, 128, degree).unwrap();
            // Evaluate the secret polynomial at 0.
            assert_eq!(polynomial.evaluate(0), secret);
            // Evaluate the secret polynomial at 1 (which should be the sum of coefficients).
            let mut coefficient_sum: FiniteFieldElement =
                FiniteFieldElement::new_integer(0, &modulus);
            for coefficient in &polynomial.coefficients {
                coefficient_sum = coefficient_sum + coefficient.clone();
            }
            assert_eq!(polynomial.evaluate(1), coefficient_sum);
        }
    }

    #[test]
    /// The function tests the reconstruction of the secret parameter in the polynomial.
    fn test_working_secret_reconstruction() {
        let mut rng = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            let secret = FiniteFieldElement::new_random(256, &get_modulus_for_bits(256).unwrap());
            let degree = rng.gen_range(2..20);
            let polynomial = SecretPolynomial::new(&secret, 256, degree).unwrap();
            // Construct a large number of shares.
            let shares = polynomial.get_secret_shares((degree * 2) as u32);
            // Select a sufficiently large subset.
            let random_shares: Vec<SecretShare> = shares
                //.into_iter()
                .choose_multiple(&mut rng, degree + 1)
                .cloned()
                .collect();
            // Reconstruct the secret.
            let reconstructed_secret = reconstruct_secret(&random_shares);
            // Assert that the secret was reconstructed correctly.
            assert_eq!(secret, reconstructed_secret);
        }
    }

    #[test]
    /// The function ensures that secret cannot be reconstructed when fewer than `degree+1`
    // shares are combined.
    fn test_failing_secret_reconstruction() {
        let modulus = &get_modulus_for_bits(256).unwrap();
        let mut rng = rand::thread_rng();
        for _test in 0..NUM_TEST_RUNS {
            let secret = FiniteFieldElement::new_random(256, modulus);
            let degree = rng.gen_range(2..20);
            let polynomial = SecretPolynomial::new(&secret, 256, degree).unwrap();
            // Construct a large number of shares.
            let shares = polynomial.get_secret_shares((degree * 2) as u32);
            // Select too few secret shares to reconstruct the secret.
            let num_secret_shares = rng.gen_range(1..degree + 1);
            let random_shares: Vec<SecretShare> = shares
                .choose_multiple(&mut rng, num_secret_shares)
                .cloned()
                .collect();
            // Attempt to reconstruct the secret.
            let reconstructed_secret = reconstruct_secret(&random_shares);
            // Assert that the secret was not reconstructed.
            assert_ne!(secret, reconstructed_secret);
        }
    }
}
