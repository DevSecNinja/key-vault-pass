//! Cryptographically strong password generation.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::error::{Error, Result};
use crate::model::GeneratePasswordOptions;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Symbols kept URL/shell-friendly while still providing good entropy.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}";

/// Generate a random password using the OS CSPRNG.
///
/// Guarantees at least one character from each selected class and shuffles the
/// result so class members are not positionally predictable.
pub fn generate_password(options: &GeneratePasswordOptions) -> Result<String> {
    let mut pools: Vec<&[u8]> = Vec::new();
    if options.use_lowercase {
        pools.push(LOWERCASE);
    }
    if options.use_uppercase {
        pools.push(UPPERCASE);
    }
    if options.use_digits {
        pools.push(DIGITS);
    }
    if options.use_symbols {
        pools.push(SYMBOLS);
    }

    if pools.is_empty() {
        return Err(Error::Configuration(
            "at least one character class must be enabled to generate a password".into(),
        ));
    }
    if options.length < pools.len() {
        return Err(Error::Configuration(format!(
            "password length {} is too short for {} required character classes",
            options.length,
            pools.len()
        )));
    }

    let mut rng = rand::rng();

    // One guaranteed character from each selected class.
    let mut chars: Vec<u8> = pools
        .iter()
        .map(|pool| pool[rng.random_range(0..pool.len())])
        .collect();

    // Fill the remainder from the combined alphabet.
    let alphabet: Vec<u8> = pools.iter().flat_map(|p| p.iter().copied()).collect();
    for _ in 0..(options.length - pools.len()) {
        chars.push(alphabet[rng.random_range(0..alphabet.len())]);
    }

    chars.shuffle(&mut rng);

    // All bytes come from ASCII pools, so this is guaranteed valid UTF-8.
    Ok(String::from_utf8(chars).expect("password bytes are ASCII"))
}
