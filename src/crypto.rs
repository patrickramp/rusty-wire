use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use curve25519_dalek::{constants, scalar::Scalar};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: String,
    pub private: String,
}

/// Generate a WireGuard-compatible X25519 keypair
pub fn generate_keypair() -> Result<KeyPair> {
    let mut rng = OsRng;
    let mut private_bytes = [0u8; 32];
    rng.try_fill_bytes(&mut private_bytes)?;
    let private_scalar = Scalar::from_bytes_mod_order(private_bytes);
    
    // Compute public key: private_key * base_point
    let public_point = &private_scalar * constants::ED25519_BASEPOINT_TABLE;
    let public_bytes = public_point.compress().to_bytes();
    
    Ok(KeyPair {
        private: STANDARD.encode(private_bytes),
        public: STANDARD.encode(public_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    
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