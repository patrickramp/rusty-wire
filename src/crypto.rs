use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: String,
    pub private: String,
}

/// Generate a WireGuard-compatible X25519 keypair
pub fn generate_keypair() -> Result<KeyPair> {
    let private_key = StaticSecret::random();
    let public_key = x25519_dalek::PublicKey::from(&private_key);

    let private_bytes = private_key.as_bytes();
    let public_bytes = public_key.as_bytes();

    Ok(KeyPair {
        private: STANDARD.encode(private_bytes),
        public: STANDARD.encode(public_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().unwrap();

        // Keys should be valid base64
        assert!(STANDARD.decode(&keypair.private).is_ok());
        assert!(STANDARD.decode(&keypair.public).is_ok());

        // Keys should be 32 bytes when decoded
        assert_eq!(STANDARD.decode(&keypair.private).unwrap().len(), 32);
        assert_eq!(STANDARD.decode(&keypair.public).unwrap().len(), 32);

        // Should generate different keys each time
        let keypair2 = generate_keypair().unwrap();
        assert_ne!(keypair.private, keypair2.private);
        assert_ne!(keypair.public, keypair2.public);
    }

    #[test]
    fn test_key_format() {
        let keypair = generate_keypair().unwrap();

        // WireGuard keys are typically 44 characters (32 bytes base64 encoded with padding)
        assert_eq!(keypair.private.len(), 44);
        assert_eq!(keypair.public.len(), 44);

        // Should end with = (base64 padding)
        assert!(keypair.private.ends_with('=') || keypair.private.ends_with("=="));
        assert!(keypair.public.ends_with('=') || keypair.public.ends_with("=="));
    }
}
