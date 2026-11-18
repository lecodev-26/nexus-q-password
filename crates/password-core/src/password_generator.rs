//! OS-random password generation with unbiased selection and Fisher-Yates shuffle.

use zeroize::Zeroizing;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordGeneratorError {
    InvalidLength,
    NoCharacterClasses,
    LengthTooShortForPolicy,
    RandomnessUnavailable,
}

impl std::fmt::Display for PasswordGeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "Password length must be between 8 and 128 characters.",
            Self::NoCharacterClasses => "Select at least one character class.",
            Self::LengthTooShortForPolicy => {
                "Password length is too short for the selected character classes."
            }
            Self::RandomnessUnavailable => "Secure random number generation is unavailable.",
        })
    }
}

impl std::error::Error for PasswordGeneratorError {}

/// Generate a password using only the operating-system CSPRNG.
///
/// At least one character from every selected class is guaranteed. Character
/// selection and the final shuffle use rejection sampling to avoid modulo bias.
pub fn generate_password(
    policy: PasswordPolicy,
) -> Result<Zeroizing<String>, PasswordGeneratorError> {
    if !(8..=128).contains(&policy.length) {
        return Err(PasswordGeneratorError::InvalidLength);
    }

    let mut classes: Vec<&[u8]> = Vec::with_capacity(4);
    if policy.lowercase {
        classes.push(LOWERCASE);
    }
    if policy.uppercase {
        classes.push(UPPERCASE);
    }
    if policy.digits {
        classes.push(DIGITS);
    }
    if policy.symbols {
        classes.push(SYMBOLS);
    }
    if classes.is_empty() {
        return Err(PasswordGeneratorError::NoCharacterClasses);
    }
    if policy.length < classes.len() {
        return Err(PasswordGeneratorError::LengthTooShortForPolicy);
    }

    let alphabet: Vec<u8> = classes
        .iter()
        .flat_map(|class| class.iter().copied())
        .collect();
    let mut output = Vec::with_capacity(policy.length);

    for class in &classes {
        output.push(class[random_below(class.len())?]);
    }
    while output.len() < policy.length {
        output.push(alphabet[random_below(alphabet.len())?]);
    }

    for index in (1..output.len()).rev() {
        let swap_index = random_below(index + 1)?;
        output.swap(index, swap_index);
    }

    // All character sets above are ASCII, so UTF-8 conversion cannot fail.
    let password = String::from_utf8(output).expect("password alphabet is ASCII");
    Ok(Zeroizing::new(password))
}

fn random_below(upper: usize) -> Result<usize, PasswordGeneratorError> {
    let upper = u32::try_from(upper).map_err(|_| PasswordGeneratorError::RandomnessUnavailable)?;
    if upper == 0 {
        return Err(PasswordGeneratorError::NoCharacterClasses);
    }
    let range = 1u64 << 32;
    let zone = range - (range % u64::from(upper));
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| PasswordGeneratorError::RandomnessUnavailable)?;
        let value = u32::from_le_bytes(bytes);
        if u64::from(value) < zone {
            return Ok((value % upper) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_obeys_length_and_selected_classes() {
        let password = generate_password(PasswordPolicy {
            length: 48,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        })
        .expect("generate");
        assert_eq!(password.len(), 48);
        assert!(password.bytes().any(|b| LOWERCASE.contains(&b)));
        assert!(password.bytes().any(|b| UPPERCASE.contains(&b)));
        assert!(password.bytes().any(|b| DIGITS.contains(&b)));
        assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn rejects_empty_character_policy() {
        let result = generate_password(PasswordPolicy {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
        });
        assert_eq!(
            result.unwrap_err(),
            PasswordGeneratorError::NoCharacterClasses
        );
    }

    #[test]
    fn rejects_out_of_range_length() {
        let result = generate_password(PasswordPolicy {
            length: 7,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
        });
        assert_eq!(result.unwrap_err(), PasswordGeneratorError::InvalidLength);
    }
}
