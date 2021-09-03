use num_bigint::{BigUint, BigInt, ToBigInt};
use num_traits::{Zero, One};
use num::{Integer};
use rand::Rng;


/// The prime number
/// 2^256-189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747
/// is used. It is the largest prime number below 2^256
/// (see https://primes.utm.edu/lists/2small/200bit.html), which means that all 256-bit numbers
/// except the 189 largest can be represented.
pub const MODULUS_ARRAY : [u32; 8] = [u32::MAX-188, u32::MAX,u32::MAX, u32::MAX,u32::MAX, u32::MAX, u32::MAX,u32::MAX];

/// Given a number and a modulus, the function returns the modular inverse.
pub(crate) fn modular_inverse(number: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus == &One::one() {
        return One::one()
    }
    let mut number = number.to_bigint().expect("Modular inverse invoked with a negative nuber.");
    let mut modulus = modulus.to_bigint().expect("Modular inverse invoked with a negative nuber.");
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
    inverse.to_biguint().expect("Modular inverse invoked with a negative nuber.")
}


pub fn get_random_number(modulus: &BigUint) -> BigUint {
    let mut gen = rand::thread_rng();
    let random_bytes = gen.gen::<[u32; 8]>();
    BigUint::from_slice(&random_bytes).modpow(&One::one(), modulus)
}

struct Polynomial {
    coefficients: Vec<BigUint>,
    modulus: BigUint
}

impl Polynomial {

    fn new(degree: u32, modulus: &BigUint) -> Self {
        let mut gen = rand::thread_rng();
        let mut coefficients = vec![];
        for _in in 0..=degree {
            coefficients.push(get_random_number(modulus));
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
