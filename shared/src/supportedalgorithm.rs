use ssh_key::{Algorithm, EcdsaCurve, HashAlg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SupportedAlgorithm {
    Dsa = 0u8,
    Ed25519 = 1u8,
    SkEd25519 = 2u8,
    SkEcdsaSha2NistP256 = 3u8,
    EcdsaNistP256 = 4u8,
    EcdsaNistP384 = 5u8,
    EcdsaNistP521 = 6u8,
    RsaSha256 = 7u8,
    RsaSha512 = 8u8,
}


impl SupportedAlgorithm {
    pub fn to_byte(&self) -> u8 {
        *self as u8
    }

    pub fn from_byte(byte: &u8) -> Option<Self> {
        match byte {
            0u8 => Some(Self::Dsa),
            1u8 => Some(Self::Ed25519),
            2u8 => Some(Self::SkEd25519),
            3u8 => Some(Self::SkEcdsaSha2NistP256),
            4u8 => Some(Self::EcdsaNistP256),
            5u8 => Some(Self::EcdsaNistP384),
            6u8 => Some(Self::EcdsaNistP521),
            7u8 => Some(Self::RsaSha256),
            8u8 => Some(Self::RsaSha512),
            _ => None,
        }
    }

    pub fn to_ssh_algorithm(&self) -> Option<Algorithm> {
        match self {
            SupportedAlgorithm::Dsa => Some(Algorithm::Dsa),
            SupportedAlgorithm::Ed25519 => Some(Algorithm::Ed25519),
            SupportedAlgorithm::SkEd25519 => Some(Algorithm::SkEd25519),
            SupportedAlgorithm::SkEcdsaSha2NistP256 => Some(Algorithm::SkEcdsaSha2NistP256),
            SupportedAlgorithm::EcdsaNistP256 => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }),
            SupportedAlgorithm::EcdsaNistP384 => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }),
            SupportedAlgorithm::EcdsaNistP521 => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }),
            SupportedAlgorithm::RsaSha256 => Some(Algorithm::Rsa { hash: Some(HashAlg::Sha256) }),
            SupportedAlgorithm::RsaSha512 => Some(Algorithm::Rsa { hash: Some(HashAlg::Sha512) }),
        }
    }

    pub fn from_ssh_algorithm(a: &Algorithm) -> Option<Self> {
        match a {
            Algorithm::Dsa => Some(SupportedAlgorithm::Dsa),
            Algorithm::Ed25519 => Some(SupportedAlgorithm::Ed25519),
            Algorithm::SkEd25519 => Some(SupportedAlgorithm::SkEd25519),
            Algorithm::SkEcdsaSha2NistP256 => Some(SupportedAlgorithm::SkEcdsaSha2NistP256),
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 } => Some(SupportedAlgorithm::EcdsaNistP256),
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 } => Some(SupportedAlgorithm::EcdsaNistP384),
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 } => Some(SupportedAlgorithm::EcdsaNistP521),
            Algorithm::Rsa { hash: Some(HashAlg::Sha256) } => Some(SupportedAlgorithm::RsaSha256),
            Algorithm::Rsa { hash: Some(HashAlg::Sha512) } => Some(SupportedAlgorithm::RsaSha512),
            _ => None
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algo_enum_flattening(){
        for i in 0_u8..9_u8{
            let algo = SupportedAlgorithm::from_byte(&i);
            assert!(algo.is_some());
            let algo = algo.unwrap();
            let back = algo.to_byte();
            assert_eq!(i, back);
            let ssh_algo = algo.to_ssh_algorithm();
            assert!(ssh_algo.is_some());
            let ssh_algo = ssh_algo.unwrap();
            let algo2 = SupportedAlgorithm::from_ssh_algorithm(&ssh_algo);
            assert!(algo2.is_some());
            let algo2 = algo2.unwrap();
            assert_eq!(algo, algo2);
        }

        // test unsupported byte
        let algo = SupportedAlgorithm::from_byte(&10u8);
        assert!(algo.is_none());
    }
}