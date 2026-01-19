mod binary;
mod crypto;
mod supportedalgorithm;

use std::path::PathBuf;
pub use ssh_key::{Certificate, PrivateKey, PublicKey, Fingerprint};
pub use ssh_key::authorized_keys::AuthorizedKeys;
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

    macro_rules! algorithm_test_okay {
        ($algo_name:ident) => {
            paste! {
                static_path!([<$algo_name:upper _ PRIV_TIME_LIMITED>], concat!("../tests/keys_limited/", stringify!($algo_name)));
                static_path!([<$algo_name:upper _ PRIV_TIME_UNLIMITED>], concat!("../tests/keys_unlimited/", stringify!($algo_name)));
                static_path!([<$algo_name:upper _ PUB_TIME_LIMITED>], concat!("../tests/keys_limited/", stringify!($algo_name), ".pub"));
                static_path!([<$algo_name:upper _ PUB_TIME_UNLIMITED>], concat!("../tests/keys_unlimited/", stringify!($algo_name), ".pub"));

                static_path_test_ok!([<$algo_name:upper _ PUB_TIME_LIMITED>], load_ca);
                static_path_test_ok!([<$algo_name:upper _ PUB_TIME_UNLIMITED>], load_ca);
                static_path_test_ok!([<$algo_name:upper _ PRIV_TIME_LIMITED>], load_private_key);
                static_path_test_ok!([<$algo_name:upper _ PRIV_TIME_UNLIMITED>], load_private_key);
            }
        }
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

    algorithm_test_okay!(ecdsa_nistp256);
    algorithm_test_okay!(ecdsa_nistp384);
    algorithm_test_okay!(ecdsa_nistp521);
    algorithm_test_okay!(ed25519);
    algorithm_test_okay!(rsa_sha256);
    algorithm_test_okay!(rsa_sha512);
}
