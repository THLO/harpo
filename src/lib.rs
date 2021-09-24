/// The math module provides the required finite field operations.
mod math;

// The mnemonic module provides the conversion between mnemonic codes and the representation as
// a finite field element.
mod mnemonic;

/// The secret_sharing module provides the secret-sharing functionality.
mod secret_sharing;

/// The default word list is loaded from a separate module.
mod word_list;

/// The function is called to create secret-shared mnemonic codes.
pub fn create_secret_shared_mnemonic_codes() {
    // Make sure that the threshold is not
    //if threshold > num_shares {
    //    return Err("Error: The threshold must not exceed the number of secret-shared mnemonic codes");
    //}
}

/// The function is called to reconstruct a mnemonic code.
pub fn reconstruct_mnemonic_code() {
    println!("TODO: This function will be invoked when reconstructing a mnemonic code.");
}
