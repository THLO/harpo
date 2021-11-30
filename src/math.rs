//! The `math` module provides all required finite field operations.
//!

use num::Integer;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::{distributions::Standard, rngs::OsRng, Rng};
use std::cmp::Ordering;
use std::ops::{Add, Div, Mul, Sub};

/// The function returns a random finite field element with the given number of bits.
///
/// The function first generates sufficiently many random bits and then applies the
/// provided modulus.
///
/// * `bits` - The size of the random number in bits.
/// * `bits` - The modulus.
pub(crate) fn get_random_number(bits: usize, modulus: &BigUint) -> BigUint {
    // Determine the required number of 32-byte integers.
    let num_elements = ((bits + 31) / 32) as usize;
    // Get the random numbers.
    let random_bytes: Vec<u32> = OsRng.sample_iter(Standard).take(num_elements).collect();
    // Construct a big unsigned integer and apply the modulus.
    BigUint::from_slice(&random_bytes).mod_floor(modulus)
}

/// Given a number and a modulus, the function returns the modular inverse.
///
/// * `number` - The number that is to be inverted.
/// * `modulus` - The modulus.
fn modular_inverse(number: &BigUint, modulus: &BigUint) -> BigUint {
    // If the modulus is 1, return 1.
    if modulus == &One::one() {
        return One::one();
    }
    let mut number = number
        .to_bigint()
        .expect("Conversion to big integer failed.");
    let mut modulus = modulus
        .to_bigint()
        .expect("Conversion to big integer failed.");
    // Use the extended Euclidean algorithm to compute the inverse.
    let original_modulus = modulus.clone();
    let mut x: BigInt = Zero::zero();
    let mut inverse: BigInt = One::one();
    while number > One::one() {
        let (dividend, remainder) = number.div_rem(&modulus);
        inverse -= dividend * &x;
        number = remainder;
        std::mem::swap(&mut number, &mut modulus);
        std::mem::swap(&mut x, &mut inverse)
    }
    // If the inverse is negative, add the modulus.
    if inverse < Zero::zero() {
        inverse += original_modulus
    }
    // Convert the inverse to an unsigned big integer.
    inverse
        .to_biguint()
        .expect("Conversion to unsigned big integer failed.")
}

#[derive(Debug, Clone, Eq)]
/// The struct holds a finite field element.
pub(crate) struct FiniteFieldElement {
    /// The value in the form of a big unsigned integer.
    pub value: BigUint,
    /// The modulus in the form of a big unsigned integer.
    pub modulus: BigUint,
}

impl FiniteFieldElement {
    /// The function creates a finite field element.
    ///
    /// * `bytes` - The bytes that define the value of the finite field element.
    /// * `modulus` - The modulus.
    pub fn new(bytes: &[u8], modulus: &BigUint) -> Self {
        let mut integers: Vec<u32> = vec![0; bytes.len() >> 2];
        // Since a big unsigned integer is composed of 32-bit integers, the provided bytes
        // are converted into an array of 32-bit integers first.
        for index in 0..(bytes.len() >> 2) {
            integers[index] = (bytes[4 * index] as u32)
                + ((bytes[4 * index + 1] as u32) << 8)
                + ((bytes[4 * index + 2] as u32) << 16)
                + ((bytes[4 * index + 3] as u32) << 24)
        }
        // Return the finite field element.
        FiniteFieldElement {
            value: BigUint::from_slice(&integers),
            modulus: modulus.clone(),
        }
    }

    /// The function creates a random finite field element.
    ///
    /// * `num_bits` - The number of random bits used to construct the finite field element.
    /// * `modulus` - The modulus.
    pub fn new_random(num_bits: usize, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: get_random_number(num_bits, modulus),
            modulus: modulus.clone(),
        }
    }

    /// The function creates a finite field element corresponding to the provided integer.
    ///
    /// * `number` - The 32-bit number.
    /// * `modulus` - The modulus.
    pub fn new_integer(number: u32, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: BigUint::from_slice(&[number]),
            modulus: modulus.clone(),
        }
    }

    /// The function returns the bytes corresponding to the finite field element.
    pub fn get_bytes(&self) -> Vec<u8> {
        // The length of the array is given by the number of bits needed to represent the modulus.
        let mut bytes: Vec<u8> = vec![0; (self.modulus.bits() >> 3) as usize];
        // Get the bytes in little-endian format.
        let value_bytes = self.value.to_bytes_le();
        bytes[..value_bytes.len()].clone_from_slice(&value_bytes[..]);
        bytes
    }
}

impl PartialOrd for FiniteFieldElement {
    /// The function defines partial order over finite field elements.
    ///
    /// `other`- The other finite field element.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FiniteFieldElement {
    /// The function defines order over finite field elements.
    ///
    /// `other`- The other finite field element.
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialEq for FiniteFieldElement {
    /// The function defines equality for finite field elements.
    ///
    /// `other`- The other finite field element.
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Add for FiniteFieldElement {
    type Output = Self;

    /// The function defines addition for finite field elements.
    ///
    /// `other`- The other finite field element.
    fn add(self, other: Self) -> Self {
        Self {
            value: (self.value + other.value).mod_floor(&self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}

impl Sub for FiniteFieldElement {
    type Output = Self;

    /// The function defines subtraction for finite field elements.
    ///
    /// `other`- The other finite field element.
    fn sub(self, other: FiniteFieldElement) -> Self {
        let value = if self.value > other.value {
            self.value - other.value
        } else {
            self.value + self.modulus.clone() - other.value
        };
        Self {
            value,
            modulus: self.modulus,
        }
    }
}

impl Mul for FiniteFieldElement {
    type Output = Self;

    /// The function defines multiplication for finite field elements.
    ///
    /// `other`- The other finite field element.
    fn mul(self, other: Self) -> Self {
        Self {
            value: (self.value * other.value).mod_floor(&self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}

impl Div for FiniteFieldElement {
    type Output = Self;

    // This directive is required because division uses multiplication with the inverse element.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, other: Self) -> Self {
        // Get the modular inverse of the other element's value.
        // The modulus of "self" is used because the first term defines the modulus of the
        // operation.
        let inverse_value = modular_inverse(&other.value, &self.modulus);
        Self {
            value: (self.value * inverse_value).mod_floor(&self.modulus),
            modulus: self.modulus.clone(),
        }
    }
}

// ******************************** TESTS ********************************

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_sharing::MODULUS_ARRAY_256;

    // Every random test is repeated this many times.
    const NUM_TEST_RUNS: u32 = 100;

    #[test]
    /// The function generates random inputs for the mod_inverse() function and verifies
    /// that the product with the inverse always yields 1.
    fn test_modular_inverse() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..NUM_TEST_RUNS {
            let num = get_random_number(256, &modulus);
            let inverse = modular_inverse(&num, &modulus);
            assert_eq!((num * inverse).mod_floor(&modulus), One::one());
        }
    }

    #[test]
    /// The function tests the addition operation over finite field elements.
    fn test_finite_field_addition() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..NUM_TEST_RUNS {
            let element_1 = FiniteFieldElement::new_random(256, &modulus);
            let element_2 = FiniteFieldElement::new_random(256, &modulus);
            let mut sum = element_1.value.clone() + element_2.value.clone();
            if sum >= modulus {
                sum -= modulus.clone();
            }
            assert_eq!((element_1 + element_2).value, sum);
        }
    }

    #[test]
    /// The function tests the subtraction operation over finite field elements.
    fn test_finite_field_subtraction() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..NUM_TEST_RUNS {
            let element_1 = FiniteFieldElement::new_random(256, &modulus);
            let element_2 = FiniteFieldElement::new_random(256, &modulus);
            let difference = if element_1 >= element_2 {
                element_1.value.clone() - element_2.value.clone()
            } else {
                element_1.value.clone() + modulus.clone() - element_2.value.clone()
            };
            assert_eq!((element_1 - element_2).value, difference);
        }
    }

    #[test]
    /// The function tests the multiplication operation over finite field elements.
    fn test_finite_field_multiplication() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..NUM_TEST_RUNS {
            let element_1 = FiniteFieldElement::new_random(256, &modulus);
            let element_2 = FiniteFieldElement::new_random(256, &modulus);
            let product = element_1.value.clone() * element_2.value.clone();
            assert_eq!((element_1 * element_2).value, product.mod_floor(&modulus));
        }
    }

    #[test]
    /// The function tests the division operation over finite field elements.
    fn test_finite_field_division() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..NUM_TEST_RUNS {
            let element_1 = FiniteFieldElement::new_random(256, &modulus);
            let element_2 = FiniteFieldElement::new_random(256, &modulus);
            let element_3 = FiniteFieldElement::new_random(256, &modulus);
            let term = (element_1.value.clone()
                * element_2.value.clone()
                * modular_inverse(&element_3.value, &modulus))
            .mod_floor(&modulus);
            assert_eq!(
                (element_1.clone() * element_2.clone() / element_3.clone()).value,
                term
            );
            assert_eq!((element_1 / element_3 * element_2).value, term);
        }
    }

    #[test]
    /// The function ensures that the finite field element is always encoded using
    /// the correct number of bytes.
    fn test_correct_byte_length() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        let mut rng = rand::thread_rng();
        for _i in 0..NUM_TEST_RUNS {
            let length = rng.gen_range(10..256);
            let element = FiniteFieldElement::new_random(length, &modulus);
            // Since a 256-bit modulus is used, 256/8 = 32 bytes should always be used.
            assert_eq!(element.get_bytes().len(), 256 >> 3);
        }
    }
}
