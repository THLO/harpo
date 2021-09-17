use num::Integer;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::distributions::Standard;
use rand::Rng;
use std::cmp::{max, Ordering};
use std::ops::{Add, Div, Mul, Sub};

#[derive(Debug, Clone, Eq)]
/// The struct holds a finite field element.
pub(crate) struct FiniteFieldElement {
    /// The value in the form of a big unsigned integer.
    pub value: BigUint,
    /// The number of bits that are used at most to represent the value.
    pub num_bits: usize,
    /// The modulus in the form of a big unsigned integer.
    pub modulus: BigUint,
}

/// The function returns a random finite field element with the given number of bits.
pub(crate) fn get_random_number(bits: usize, modulus: &BigUint) -> BigUint {
    // Determine the required number of 32-byte integers.
    let num_elements = ((bits + 31) / 32) as usize;
    // Get the random numbers.
    let random_bytes: Vec<u32> = rand::thread_rng()
        .sample_iter(Standard)
        .take(num_elements)
        .collect();
    // Construct a big unsigned integer and apply the modulus.
    BigUint::from_slice(&random_bytes).modpow(&One::one(), modulus)
}

/// Given a number and a modulus, the function returns the modular inverse.
fn modular_inverse(number: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus == &One::one() {
        return One::one();
    }
    let mut number = number
        .to_bigint()
        .expect("Conversion to big integer failed.");
    let mut modulus = modulus
        .to_bigint()
        .expect("Conversion to big integer failed.");
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
    if inverse < Zero::zero() {
        inverse += original_modulus
    }
    inverse
        .to_biguint()
        .expect("Conversion to unsigned big integer failed..")
}

impl FiniteFieldElement {
    pub fn new(value: &BigUint, num_bits: usize, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: value.clone(),
            num_bits,
            modulus: modulus.clone(),
        }
    }

    pub fn new_random(num_bits: usize, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: get_random_number(num_bits, modulus),
            num_bits,
            modulus: modulus.clone(),
        }
    }

    pub fn new_integer(value: u32, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: BigUint::from_slice(&[value]),
            num_bits: 1,
            modulus: modulus.clone(),
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0; self.num_bits >> 3];
        let value_bytes = self.value.to_bytes_le();
        bytes[..value_bytes.len()].clone_from_slice(&value_bytes[..]);
        bytes
    }
}

impl PartialOrd for FiniteFieldElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FiniteFieldElement {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialEq for FiniteFieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Add for FiniteFieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            value: (self.value + other.value).modpow(&One::one(), &self.modulus),
            num_bits: max(self.num_bits, other.num_bits),
            modulus: self.modulus.clone(),
        }
    }
}

impl Sub for FiniteFieldElement {
    type Output = Self;

    fn sub(self, other: FiniteFieldElement) -> Self {
        let value = if self.value > other.value {
            self.value - other.value
        } else {
            self.value + self.modulus.clone() - other.value
        };
        Self {
            value,
            num_bits: max(self.num_bits, other.num_bits),
            modulus: self.modulus,
        }
    }
}

impl Mul for FiniteFieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self {
            value: (self.value * other.value).modpow(&One::one(), &self.modulus),
            num_bits: max(self.num_bits, other.num_bits),
            modulus: self.modulus.clone(),
        }
    }
}

impl Div for FiniteFieldElement {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, other: Self) -> Self {
        // Get the moduluar inverse of the other element's value.
        // The modulus of "self" is used because the first term defines the modulus of the
        // operation.
        let inverse_value = modular_inverse(&other.value, &self.modulus);
        Self {
            value: (self.value * inverse_value).modpow(&One::one(), &self.modulus),
            num_bits: max(self.num_bits, other.num_bits),
            modulus: self.modulus.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_sharing::MODULUS_ARRAY_256;

    #[test]
    /// The function generates random inputs for the mod_inverse() function and verifies
    /// that the product with the inverse always yields 1.
    fn test_modular_inverse() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..10 {
            let one = One::one();
            let num = get_random_number(256, &modulus);
            let inverse = modular_inverse(&num, &modulus);
            assert_eq!((num * inverse).modpow(&one, &modulus), one);
        }
    }

    #[test]
    /// The function tests the addition operation over finite field elements.
    fn test_finite_field_addition() {
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..10 {
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
        for _i in 0..10 {
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
        let one = One::one();
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..10 {
            let element_1 = FiniteFieldElement::new_random(256, &modulus);
            let element_2 = FiniteFieldElement::new_random(256, &modulus);
            let product = element_1.value.clone() * element_2.value.clone();
            assert_eq!(
                (element_1 * element_2).value,
                product.modpow(&one, &modulus)
            );
        }
    }

    #[test]
    /// The function tests the division operation over finite field elements.
    fn test_finite_field_division() {
        let one = One::one();
        let modulus = BigUint::from_slice(&MODULUS_ARRAY_256);
        for _i in 0..10 {
            let element_1 = FiniteFieldElement::new_random(256, &modulus);
            let element_2 = FiniteFieldElement::new_random(256, &modulus);
            let element_3 = FiniteFieldElement::new_random(256, &modulus);
            let term = (element_1.value.clone()
                * element_2.value.clone()
                * modular_inverse(&element_3.value, &modulus))
            .modpow(&one, &modulus);
            assert_eq!(
                (element_1.clone() * element_2.clone() / element_3.clone()).value,
                term
            );
            assert_eq!((element_1 / element_3 * element_2).value, term);
        }
    }
}
