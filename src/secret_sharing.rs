use num_bigint::BigUint;
use num_traits::One;
use crate::math::{FiniteFieldElement, get_random_number};
use std::fmt;

/// For each modulus, the largest prime number is used for each bit length.
/// These prime numbers can be found here: https://primes.utm.edu/lists/2small/200bit.html

/// The prime number
/// 2^128-159 = 340282366920938463463374607431768211297
/// is used for 128-bit inputs.
pub const MODULUS_ARRAY_128 : [u32; 4] = [u32::MAX-158, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^160-47 = 1461501637330902918203684832716283019655932542929
/// is used for 160-bit inputs.
pub const MODULUS_ARRAY_160 : [u32; 5] = [u32::MAX-46, u32::MAX, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^192-237 = 6277101735386680763835789423207666416102355444464034512659
/// is used for 192-bit inputs.
pub const MODULUS_ARRAY_192 : [u32; 6] = [u32::MAX-236, u32::MAX,u32::MAX, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^224-63 = 26959946667150639794667015087019630673637144422540572481103610249153
/// is used for 224-bit inputs.
pub const MODULUS_ARRAY_224 : [u32; 7] = [u32::MAX-62, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX];

/// The prime number
/// 2^256-189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747
/// is used for 256-bit inputs.
pub const MODULUS_ARRAY_256 : [u32; 8] = [u32::MAX-188, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX];

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

    fn new(degree: u32, num_bits: u32, modulus: &BigUint) -> Self {
        let mut coefficients = vec![];
        for _in in 0..=degree {
            coefficients.push(get_random_number(num_bits, modulus));
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
    use num_traits::Zero;

    #[test]
    /// The function tests the evaluation of a polynomial:
    fn test_polynomial_evaluation() {
        let modulus = BigUint::from_slice(&[127]);
        let polynomial = Polynomial::new(2, 7, &modulus);
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
