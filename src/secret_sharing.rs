use num_bigint::BigUint;
use num_traits::One;
use crate::math::{FiniteFieldElement, get_random_number};
use std::fmt;

/// The prime number
/// 2^256-189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747
/// is used. It is the largest prime number below 2^256
/// (see https://primes.utm.edu/lists/2small/200bit.html), which means that all 256-bit numbers
/// except the 189 largest can be represented.
pub const MODULUS_ARRAY : [u32; 8] = [u32::MAX-188, u32::MAX,u32::MAX, u32::MAX,u32::MAX, u32::MAX, u32::MAX,u32::MAX];

pub const MODULUS_SIZE_BITS : u32 = 256;

struct Polynomial {
    coefficients: Vec<BigUint>,
    modulus: BigUint
}

struct SecretShare {
    index: u32,
    element: FiniteFieldElement
}

impl fmt::Display for SecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.index, self.element.value)
    }
}

impl Polynomial {

    fn new(degree: u32, modulus: &BigUint) -> Self {
        let mut coefficients = vec![];
        for _in in 0..=degree {
            coefficients.push(get_random_number(MODULUS_SIZE_BITS, modulus));
        }
        Polynomial {
            coefficients, modulus: modulus.clone()
        }
    }

    fn evaluate(&self, value: &BigUint) -> BigUint {
        let degree = self.coefficients.len()-1;
        let mut result = self.coefficients[degree].clone();
        for index in (0..degree).rev() {
            result = result*value + self.coefficients[index].clone();
            result = result.modpow(&One::one(), &self.modulus);
        }
        result
    }
}

// ******************************** TESTS ********************************

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// The function tests the evaluation of a polynomial:
    fn test_polynomial_evaluation() {
        let modulus = BigUint::from_slice(&[127]);
        let polynomial = Polynomial::new(2, &modulus);
        // Evaluate the polynomial at 0:
        assert_eq!(polynomial.evaluate(&Zero::zero()), polynomial.coefficients[0]);
        // Evaluate the polynomial at 1 (which should be the sum of coefficients):
        let mut coefficient_sum : BigUint = Zero::zero();
        for coefficient in &polynomial.coefficients {
            coefficient_sum += coefficient;
        }
        assert_eq!(polynomial.evaluate(&One::one()), coefficient_sum.modpow(&One::one(), &modulus));
    }
}
