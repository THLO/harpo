use num_bigint::{BigUint, BigInt, ToBigInt};
use num_traits::{Zero, One};
use num::Integer;
use rand::Rng;
use rand::distributions::Standard;
use std::ops::{Add, Sub, Mul, Div};

#[derive(Debug)]
pub(crate) struct FiniteFieldElement {
    pub value: BigUint,
    pub modulus: BigUint
}

pub(crate) fn get_random_number(bits: u32, modulus: &BigUint) -> BigUint {
    let num_elements = ((bits+31)/32) as usize;
    let random_bytes : Vec<u32> = rand::thread_rng().sample_iter(Standard).take(num_elements).collect();
    BigUint::from_slice(&random_bytes).modpow(&One::one(), modulus)
}

/// Given a number and a modulus, the function returns the modular inverse.
fn modular_inverse(number: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus == &One::one() {
        return One::one()
    }
    let mut number = number.to_bigint().expect("Conversion to big integer failed.");
    let mut modulus = modulus.to_bigint().expect("Conversion to big integer failed.");
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
    inverse.to_biguint().expect("Conversion to unsigned big integer failed..")
}


impl FiniteFieldElement {

    fn new(value: &BigUint, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: value.clone(),
            modulus: modulus.clone()
        }
    }

    fn new_random(bits: u32, modulus: &BigUint) -> Self {
        FiniteFieldElement {
            value: get_random_number(bits, modulus),
            modulus: modulus.clone()
        }
    }

    fn new_integer(value: u32, modulus: &BigUint) -> Self{
        FiniteFieldElement {
            value: BigUint::from_slice(&[value]),
            modulus: modulus.clone()
        }
    }
}

impl Add for FiniteFieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            value: (self.value + other.value).modpow(&One::one(), &self.modulus),
            modulus: self.modulus.clone()
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
            modulus: self.modulus.clone()
        }
    }
}

impl Mul for FiniteFieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self {
            value: (self.value * other.value).modpow(&One::one(), &self.modulus),
            modulus: self.modulus.clone()
        }
    }
}

impl Div for FiniteFieldElement {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        // Get the moduluar inverse of the other element's value.
        // The modulus of "self" is used because the first term defines the modulus of the
        // operation.
        let inverse_value = modular_inverse(&other.value, &self.modulus);
        Self {
            value: (self.value * inverse_value).modpow(&One::one(), &self.modulus),
            modulus: self.modulus.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harpo::MODULUS_ARRAY;

    #[test]
    /// The function generates random inputs for the mod_inverse() function and verifies
    /// that the product with the inverse always yields 1.
    fn test_modular_inverse() {
        for _i in 0..10 {
            let modulus = BigUint::from_slice(&MODULUS_ARRAY);
            let one = One::one();
            let num = get_random_number(&modulus);
            let inverse = modular_inverse(&num, &modulus);
            assert_eq!((num*inverse).modpow(&one, &modulus), one);
        }
    }
}
