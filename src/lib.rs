/// The math module provides the required finite field operations.
mod math;

/// The secret_sharing module provides the secret-sharing functionality.
mod secret_sharing;

/// The default word list is loaded from a separate module.
mod word_list;

/// The function is called to create secret-shared passphrases.
pub fn create() {
    println!("TODO: This function will be invoked when creating shares.");
}

/// The function is called to reconstruct a passphrase.
pub fn reconstruct() {
    println!("TODO: This function will be invoked when reconstructing a passphrase.");
}
