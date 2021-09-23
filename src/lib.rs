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
pub fn create() {
    println!("TODO: This function will be invoked when creating secret-shared mnemonic codes.");
}

/// The function is called to reconstruct a mnemonic code.
pub fn reconstruct() {
    println!("TODO: This function will be invoked when reconstructing a mnemonic code.");
}
