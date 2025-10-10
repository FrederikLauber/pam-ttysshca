mod binary;
mod crypto;
mod supportedalgorithm;

use std::path::PathBuf;
pub use ssh_key::{Certificate, PrivateKey, PublicKey};
pub use crate::crypto::{CertificateMatches, Challenge, Answer, AnswerEngine, PrivateKeyAndCertificate};
pub use crate::binary::{Binary, IntoBinary};

pub fn load_ca(path: &PathBuf) -> Result<PublicKey, String>{
    PublicKey::read_openssh_file(path).map_err(|e| format!("Could not load ca keys file: {}", e))
}

pub fn load_private_key(path: &PathBuf) -> Result<PrivateKey, String>{
    PrivateKey::read_openssh_file(path).map_err(|e| format!("Could not load private keys file: {}", e))
}

pub fn load_certificate(path: &PathBuf) -> Result<Certificate, String>{
    Certificate::read_file(path).map_err(|e| format!("Could not intermediate cert file: {}", e))
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use paste::paste;
    use super::*;

    macro_rules! static_path {
        ($var_name:ident, $path:expr) => {
            static $var_name: Lazy<PathBuf> = Lazy::new(|| {
                let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                path.push($path);
                path
            });
        };
    }

    macro_rules! static_path_test_ok {
        ($var_name:meta, $func:expr) => {
            paste! {
                #[test]
                #[allow(non_snake_case)]
                fn [<test_static_path_ $var_name>]() {
                    if let Err(msg) = $func(&$var_name) {
                        println!("{}", msg);
                        assert!(false)
                    }
                }
            }
        };
    }
    
    static_path!(CA1_PUB, "../tests/CAs/ca1.pub");
    static_path!(CA2_PUB, "../tests/CAs/ca2.pub");
    static_path!(CA1_PRIV, "../tests/CAs/ca1");
    static_path!(CA2_PRIV, "../tests/CAs/ca2");


    static_path!(SIGNED_PRIV, "../tests/signed");
    static_path!(SIGNED_CERT, "../tests/signed-cert.pub");

    static_path!(SIGNED_FALSE_PRIV, "../tests/signed_false");
    static_path!(SIGNED_FALSE_CERT, "../tests/signed_false-cert.pub");

    static_path_test_ok!(SIGNED_FALSE_PRIV, load_private_key);
    static_path_test_ok!(SIGNED_PRIV, load_private_key);
    static_path_test_ok!(CA1_PRIV, load_private_key);
    static_path_test_ok!(CA2_PRIV, load_private_key);

    static_path_test_ok!(CA1_PUB, load_ca);
    static_path_test_ok!(CA2_PUB, load_ca);

    static_path_test_ok!(SIGNED_CERT, load_certificate);
    static_path_test_ok!(SIGNED_FALSE_CERT, load_certificate);


    static_path!(ECDSA_NISTP256_PRIV, "../tests/keys/ecdsa_nistp256");
    static_path!(ECDSA_NISTP384_PRIV, "../tests/keys/ecdsa_nistp384");
    //static_path!(ECDSA_NISTP521_PRIV, "../tests/keys/ecdsa_nistp521"); // p521 is apparently broken in ssh_key 0.6.7
    static_path!(ED25519_PRIV, "../tests/keys/ed25519");
    static_path!(_RSA_SHA256_PRIV, "../tests/keys/rsa_sha256");
    static_path!(_RSA_SHA512_PRIV, "../tests/keys/rsa_sha512");
    
    static_path_test_ok!(ECDSA_NISTP256_PRIV, load_private_key);
    static_path_test_ok!(ECDSA_NISTP384_PRIV, load_private_key);
    //static_path_test_ok!(ECDSA_NISTP521_PRIV, load_private_key);  //broken in ssh_key in 0.6.7 but preleases are broken
    static_path_test_ok!(ED25519_PRIV, load_private_key);
    //static_path_test_ok!(RSA_SHA256_PRIV, load_private_key);  //broken in ssh_key in 0.6.7 but preleases are broken
    //static_path_test_ok!(RSA_SHA512_PRIV, load_private_key);  //broken in ssh_key in 0.6.7 but preleases are broken

    static_path!(ECDSA_NISTP256_PUB, "../tests/keys/ecdsa_nistp256.pub");
    static_path!(ECDSA_NISTP384_PUB, "../tests/keys/ecdsa_nistp384.pub");
    static_path!(ECDSA_NISTP521_PUB, "../tests/keys/ecdsa_nistp521.pub");
    static_path!(ED25519_PUB, "../tests/keys/ed25519.pub");
    static_path!(RSA_SHA256_PUB, "../tests/keys/rsa_sha256.pub");
    static_path!(RSA_SHA512_PUB, "../tests/keys/rsa_sha512.pub");

    static_path_test_ok!(ECDSA_NISTP256_PUB, load_ca);
    static_path_test_ok!(ECDSA_NISTP384_PUB, load_ca);
    static_path_test_ok!(ECDSA_NISTP521_PUB, load_ca);
    static_path_test_ok!(ED25519_PUB, load_ca);
    static_path_test_ok!(RSA_SHA256_PUB, load_ca);
    static_path_test_ok!(RSA_SHA512_PUB, load_ca);
    
    static_path!(ECDSA_NISTP256_ECDSA_NISTP384_CERT, "../tests/keys/ecdsa_nistp256-ecdsa_nistp384.cert");
    static_path!(ECDSA_NISTP256_ECDSA_NISTP521_CERT, "../tests/keys/ecdsa_nistp256-ecdsa_nistp521.cert");
    static_path!(ECDSA_NISTP256_ED25519_CERT, "../tests/keys/ecdsa_nistp256-ed25519.cert");
    static_path!(ECDSA_NISTP256_RSA_SHA256_CERT, "../tests/keys/ecdsa_nistp256-rsa_sha256.cert");
    static_path!(ECDSA_NISTP256_RSA_SHA512_CERT, "../tests/keys/ecdsa_nistp256-rsa_sha512.cert");
    static_path!(ECDSA_NISTP384_ECDSA_NISTP256_CERT, "../tests/keys/ecdsa_nistp384-ecdsa_nistp256.cert");
    static_path!(ECDSA_NISTP384_ECDSA_NISTP521_CERT, "../tests/keys/ecdsa_nistp384-ecdsa_nistp521.cert");
    static_path!(ECDSA_NISTP384_ED25519_CERT, "../tests/keys/ecdsa_nistp384-ed25519.cert");
    static_path!(ECDSA_NISTP384_RSA_SHA256_CERT, "../tests/keys/ecdsa_nistp384-rsa_sha256.cert");
    static_path!(ECDSA_NISTP384_RSA_SHA512_CERT, "../tests/keys/ecdsa_nistp384-rsa_sha512.cert");
    static_path!(ECDSA_NISTP521_ECDSA_NISTP256_CERT, "../tests/keys/ecdsa_nistp521-ecdsa_nistp256.cert");
    static_path!(ECDSA_NISTP521_ECDSA_NISTP384_CERT, "../tests/keys/ecdsa_nistp521-ecdsa_nistp384.cert");
    static_path!(ECDSA_NISTP521_ED25519_CERT, "../tests/keys/ecdsa_nistp521-ed25519.cert");
    static_path!(ECDSA_NISTP521_RSA_SHA256_CERT, "../tests/keys/ecdsa_nistp521-rsa_sha256.cert");
    static_path!(ECDSA_NISTP521_RSA_SHA512_CERT, "../tests/keys/ecdsa_nistp521-rsa_sha512.cert");
    static_path!(ED25519_ECDSA_NISTP256_CERT, "../tests/keys/ed25519-ecdsa_nistp256.cert");
    static_path!(ED25519_ECDSA_NISTP384_CERT, "../tests/keys/ed25519-ecdsa_nistp384.cert");
    static_path!(ED25519_ECDSA_NISTP521_CERT, "../tests/keys/ed25519-ecdsa_nistp521.cert");
    static_path!(ED25519_RSA_SHA256_CERT, "../tests/keys/ed25519-rsa_sha256.cert");
    static_path!(ED25519_RSA_SHA512_CERT, "../tests/keys/ed25519-rsa_sha512.cert");
    static_path!(RSA_SHA256_ECDSA_NISTP256_CERT, "../tests/keys/rsa_sha256-ecdsa_nistp256.cert");
    static_path!(RSA_SHA256_ECDSA_NISTP384_CERT, "../tests/keys/rsa_sha256-ecdsa_nistp384.cert");
    static_path!(RSA_SHA256_ECDSA_NISTP521_CERT, "../tests/keys/rsa_sha256-ecdsa_nistp521.cert");
    static_path!(RSA_SHA256_ED25519_CERT, "../tests/keys/rsa_sha256-ed25519.cert");
    static_path!(RSA_SHA256_RSA_SHA512_CERT, "../tests/keys/rsa_sha256-rsa_sha512.cert");
    static_path!(RSA_SHA512_ECDSA_NISTP256_CERT, "../tests/keys/rsa_sha512-ecdsa_nistp256.cert");
    static_path!(RSA_SHA512_ECDSA_NISTP384_CERT, "../tests/keys/rsa_sha512-ecdsa_nistp384.cert");
    static_path!(RSA_SHA512_ECDSA_NISTP521_CERT, "../tests/keys/rsa_sha512-ecdsa_nistp521.cert");
    static_path!(RSA_SHA512_ED25519_CERT, "../tests/keys/rsa_sha512-ed25519.cert");
    static_path!(RSA_SHA512_RSA_SHA256_CERT, "../tests/keys/rsa_sha512-rsa_sha256.cert");

    static_path_test_ok!(ECDSA_NISTP256_ECDSA_NISTP384_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP256_ECDSA_NISTP521_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP256_ED25519_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP256_RSA_SHA256_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP256_RSA_SHA512_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP384_ECDSA_NISTP256_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP384_ECDSA_NISTP521_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP384_ED25519_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP384_RSA_SHA256_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP384_RSA_SHA512_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP521_ECDSA_NISTP256_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP521_ECDSA_NISTP384_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP521_ED25519_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP521_RSA_SHA256_CERT, load_certificate);
    static_path_test_ok!(ECDSA_NISTP521_RSA_SHA512_CERT, load_certificate);
    static_path_test_ok!(ED25519_ECDSA_NISTP256_CERT, load_certificate);
    static_path_test_ok!(ED25519_ECDSA_NISTP384_CERT, load_certificate);
    static_path_test_ok!(ED25519_ECDSA_NISTP521_CERT, load_certificate);
    static_path_test_ok!(ED25519_RSA_SHA256_CERT, load_certificate);
    static_path_test_ok!(ED25519_RSA_SHA512_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA256_ECDSA_NISTP256_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA256_ECDSA_NISTP384_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA256_ECDSA_NISTP521_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA256_ED25519_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA256_RSA_SHA512_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA512_ECDSA_NISTP256_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA512_ECDSA_NISTP384_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA512_ECDSA_NISTP521_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA512_ED25519_CERT, load_certificate);
    static_path_test_ok!(RSA_SHA512_RSA_SHA256_CERT, load_certificate);
}
