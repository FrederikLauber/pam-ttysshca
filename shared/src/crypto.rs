use std::ffi::CStr;
use std::fmt;
pub use ssh_key::{Certificate, Fingerprint, HashAlg, PrivateKey, Signature};
use ssh_key::{PublicKey, SshSig};
use crate::binary::{Binary, DisplayBinary, IntoBinary};
use crate::supportedalgorithm::SupportedAlgorithm;

const NAMESPACE: &str = "Pamttysshca";



pub trait AnswerEngine {
    fn generate_answer(&self, challenge: &Challenge) -> Result<Answer, String>;
}

/**
 * Usecase: you want to generate an answer from the raw files, not a yubikey etc.
 */
pub struct PrivateKeyAndCertificate {
    private: PrivateKey,
    intermediate: Certificate

}

pub trait CertificateMatches{
    fn matches(&self, certificate: &Certificate) -> Result<(), &'static str>;
}

impl CertificateMatches for PrivateKey{
    fn matches(&self, certificate: &Certificate) -> Result<(), &'static str> {
        let pub_from_private = self.public_key();
        pub_from_private.matches(certificate)
    }
}

impl CertificateMatches for PublicKey{
    fn matches(&self, certificate: &Certificate) -> Result<(), &'static str> {
        let pub_from_private = self.key_data();
        let pub_from_intermediate = certificate.public_key();

        if pub_from_private != pub_from_intermediate {
            Err("Certificate does not match the provided  keys")
        } else {
            Ok(())
        }
    }
}



impl PrivateKeyAndCertificate {
    /**
    * Do some basic checks (does the private keys belong to the certificate? etc.)
    */
    pub fn new(private: PrivateKey, intermediate: Certificate) -> Result<Self, &'static str> {
        private.matches(&intermediate)?;
        Ok(Self { private, intermediate })
    }
}

impl AnswerEngine for PrivateKeyAndCertificate {
    fn generate_answer(&self, challenge: &Challenge) -> Result<Answer, String> {
        let data: &[u8] = challenge.0.as_ref();

        let sshsig = self.private.sign(NAMESPACE, HashAlg::Sha256, data).map_err(|e| format!("Could not sign challenge: {}", e))?;
        let signature = sshsig.signature();
        Ok(Answer{signature: signature.clone(), intermediate: self.intermediate.clone()})
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Challenge([u8; 32]);
pub struct Answer{
    pub signature: Signature,
    pub intermediate: Certificate
}

impl PartialEq for Answer {
    fn eq(&self, other: &Answer) -> bool{
        // we do not care about comments so exclude them from comparison
        self.signature.algorithm() == other.signature.algorithm() &&
        self.signature.as_bytes() == other.signature.as_bytes() &&
        self.intermediate.algorithm() == other.intermediate.algorithm() &&
        self.intermediate.signature() == other.intermediate.signature()
    }

    fn ne(&self, other: &Answer) -> bool {
        ! self.eq(other)
    }

}

impl Answer {
    pub fn verify_signature(&self, challenge: &Challenge) -> Result<(), &'static str> {
        let keydata = self.intermediate.public_key().clone();
        let pubkey = PublicKey::new(keydata.clone(), String::new());

        let sig = SshSig::new(
            keydata,
            NAMESPACE,
            HashAlg::Sha256,
            self.signature.clone()
        ).map_err(|_| "invalid signature format")?;

        pubkey
            .verify(NAMESPACE, &challenge.0, &sig)
            .map_err(|_| "signature mismatch")
    }

    pub fn verify_intermediate(&self, ca_fingerprints: &[Fingerprint], expected_principal: &str) -> Result<(), &'static str> {
        // follow https://docs.rs/ssh-key/latest/ssh_key/certificate/struct.Certificate.html
        self.intermediate.validate(ca_fingerprints).map_err(|_| "Intermediate was not signed by CA")?;

        if !self.intermediate.valid_principals().iter().any(|p| p == expected_principal) {
            return Err("Not valid for user");
        }
        Ok(())
    }
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slice: &[u8] = self.0.as_ref();
        let wrapped_slice: &[&[u8]] = &[slice];
        write!(f, "{}", DisplayBinary(wrapped_slice))
    }
}

impl From<Challenge> for Binary {
    fn from(s: Challenge) -> Self {
        Binary(vec![s.0.to_vec()])
    }
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let algo = SupportedAlgorithm::from_ssh_algorithm(&self.intermediate.algorithm()).ok_or_else(|| std::fmt::Error)?.to_byte();
        let algo_byte = vec![algo];
        let raw_bytes = self.signature.as_bytes();
        let certificate_bytes = self.intermediate.to_bytes().map_err(|_| std::fmt::Error)?;

        write!(f, "{}", DisplayBinary{ 0: &*vec![&algo_byte, raw_bytes, &certificate_bytes] })
    }
}


impl TryFrom<Binary> for Answer {
    type Error = &'static str;

    fn try_from(s: Binary) -> Result<Self, Self::Error> {
        if s.len() != 3 {
            return Err("Expected 3 binary blobs");
        }

        let algo = SupportedAlgorithm::from_byte(&s.0[0][0]).ok_or_else(|| "Unsupported algorithm")?;
        let raw_bytes = s.0[1].clone();
        let cert = Certificate::from_bytes(&*s.0[2].clone()).map_err(|_| "Invalid Certificate")?;
        let tmp1 = Signature::new(algo.to_ssh_algorithm().ok_or_else(|| "Invalid Certificate")?, raw_bytes).map_err(|_| "Invalid signature")?;
        Ok(Answer{signature: tmp1, intermediate: cert})
    }
}

impl TryFrom<String> for Answer {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Answer::try_from(s.into_binary()?)
    }
}

impl TryFrom<&String> for Answer {
    type Error = &'static str;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Answer::try_from(s.into_binary()?)
    }
}


impl TryFrom<&str> for Answer {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Answer::try_from(s.into_binary()?)
    }
}

impl TryFrom<&CStr> for Answer {
    type Error = &'static str;

    fn try_from(s: &CStr) -> Result<Self, Self::Error> {
        Answer::try_from(s.into_binary()?)
    }
}

impl TryFrom<Answer> for Binary {
    type Error = &'static str;

    fn try_from(s: Answer) -> Result<Self, Self::Error> {
        let raw_bytes = s.signature.as_bytes().to_vec();
        let algo = SupportedAlgorithm::from_ssh_algorithm(&s.signature.algorithm()).ok_or_else(|| "Unsupported algorithm")?.to_byte();
        let algo_byte = vec![algo];
        let certificate_bytes = s.intermediate.to_bytes().map_err(|_| "Unsupported intermediate")?;
        let tmp = vec![algo_byte, raw_bytes, certificate_bytes];
        Ok(Binary{0: tmp})
    }
}

impl Challenge {
    pub fn new() ->Challenge{
        let entropy: [u8; 32] = rand::random();
        Challenge(entropy)
    }
}

impl TryFrom<Binary> for Challenge {
    type Error = &'static str;

    fn try_from(s: Binary) -> Result<Self, Self::Error> {
        let tmp: [u8; 32] = s.0[0].clone().try_into().map_err(|_| "Too much data")?;
        Ok(Challenge(tmp))
    }
}


impl TryFrom<String> for Challenge {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Challenge::try_from(s.into_binary()?)
    }
}

impl TryFrom<&String> for Challenge {
    type Error = &'static str;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Challenge::try_from(s.into_binary()?)
    }
}


impl TryFrom<&str> for Challenge {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Challenge::try_from(s.into_binary()?)
    }
}

impl TryFrom<&CStr> for Challenge {
    type Error = &'static str;

    fn try_from(s: &CStr) -> Result<Self, Self::Error> {
        Challenge::try_from(s.into_binary()?)
    }
}


#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::path::PathBuf;
    use std::{slice};
    use std::str::FromStr;
    use ssh_key::Algorithm;
    use crate::crypto::Signature;
    use crate::{load_ca, load_certificate, load_private_key};
    use super::*;
    use paste::paste;
    use std::fs;

    #[test]
    fn test_challengebackandforth() {
        let challenge = Challenge::new();
        let serialized = challenge.to_string();
        let read_challenge = Challenge::try_from(&serialized).unwrap();
        assert!(challenge == read_challenge);
    }

    #[test]
    fn test_answerbackandforth() {
        let bytes: [u8; 64] = rand::random();
        let sig = Signature::new(Algorithm::Ed25519, bytes).unwrap();
        let path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();
        let cert = load_certificate(&path).unwrap();
        let answer = Answer { signature: sig, intermediate: cert };
        let serialized = answer.to_string();
        let read_answer = Answer::try_from(&serialized).unwrap();
        // I am not copying the comments to save bytes but that means I have to manually compare
        assert!(answer == read_answer);
        assert!(! (answer != read_answer))  // just so we hit the ne as well
    }

    #[test]
    fn test_signing_proper() {
        let challenge = Challenge::new();
        let ca_path = PathBuf::from_str("../tests/CAs/ca1.pub").unwrap();
        let private_path = PathBuf::from_str("../tests/signed").unwrap();
        let cert_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();

        let ca = load_ca(&ca_path).unwrap();
        let fingerprint = ca.fingerprint(Default::default());
        let private = load_private_key(&private_path).unwrap();
        let certificate = load_certificate(&cert_path).unwrap();
        
        let engine = PrivateKeyAndCertificate::new(private, certificate).unwrap();
        let answer = engine.generate_answer(&challenge).unwrap();
        answer.verify_signature(&challenge).unwrap();
        answer.verify_intermediate(slice::from_ref(&fingerprint), "testuser").unwrap();
        assert_eq!(answer.verify_intermediate(slice::from_ref(&fingerprint), "testuser_false"), Err("Not valid for user"));
    }

    #[test]
    fn test_signing_random_ca_fails() {
        let challenge = Challenge::new();

        let ca_path = PathBuf::from_str("../tests/CAs/ca1.pub").unwrap();
        let private_path_false = PathBuf::from_str("../tests/signed_false").unwrap();
        let cert_path_false = PathBuf::from_str("../tests/signed_false-cert.pub").unwrap();

        let ca = load_ca(&ca_path).unwrap();
        let fingerprint = ca.fingerprint(Default::default());

        let private_false = load_private_key(&private_path_false).unwrap();
        let certificate_false = load_certificate(&cert_path_false).unwrap();

        let engine_false = PrivateKeyAndCertificate::new(private_false, certificate_false).unwrap();
        let answer_false = engine_false.generate_answer(&challenge).unwrap();
        answer_false.verify_signature(&challenge).unwrap();
        assert!(answer_false.verify_intermediate(slice::from_ref(&fingerprint), "testuser").is_err());
    }

    #[test]
    fn test_signing_faked_signature() {
        let challenge = Challenge::new();
        let ca_path = PathBuf::from_str("../tests/CAs/ca1.pub").unwrap();

        let private_path_false = PathBuf::from_str("../tests/signed_false").unwrap();
        let cert_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();
        let cert_path_false = PathBuf::from_str("../tests/signed_false-cert.pub").unwrap();

        let ca = load_ca(&ca_path).unwrap();
        let fingerprint = ca.fingerprint(Default::default());

        let private_false = load_private_key(&private_path_false).unwrap();
        let certificate = load_certificate(&cert_path).unwrap();
        let certificate_false = load_certificate(&cert_path_false).unwrap();

        let engine_false = PrivateKeyAndCertificate::new(private_false, certificate_false).unwrap();
        let answer_false = engine_false.generate_answer(&challenge).unwrap();

        let modified_answer = Answer{signature: answer_false.signature, intermediate: certificate};

        //intermediate matches
        modified_answer.verify_intermediate(slice::from_ref(&fingerprint), "testuser").unwrap();
        // the signature matches the challenge but not the intermediate
        assert!(modified_answer.verify_signature(&challenge).is_err());
    }

    #[test]
    fn test_binary2answer_but_not_3_blobs(){
        let binary = Binary{0: Vec::new()};
        assert!(Answer::try_from(binary).is_err())
    }

    #[test]
    fn test_challenge2answer(){
        let challenge = Challenge::new();
        let _binary = Binary::from(challenge);
    }

    #[test]
    fn test_answer_string2answer(){
        let answer_string = "[[[0R:r#_c@ElzkUJr7*Uu17uvrN@B%;-U>Qqj#y@{KnOyL<L!a2tY_S>N;uv%y1zTaRtZff<Vt<$Z4#6Itu&<:0000Wb8~1dWn?lnH8D9YV`Xx5Ep{+5KyPqmZgX>JE@N+P0000W@6eqn1dj9(Z0ZI-kiyUZ!YHR*k)zAYKgNv`W=8ME0000WAl)rJ)FEJ|d@Zy`jdI?<;)*c^slX9E!17Y>aB$}`0000000000000010000KbY*jNb#rBMKxKGgZE$R5E@N+P0000C00008bY*jNb#rBM00000X#&1500000d%=>W000000001j0000LaAk6BX>=`EF)=M>Z*q5Ga%5?4X8-^I000007jR{AZE18ZVP|D-bS-9Ya(7{JWNB_^000000000MaAk6BX>=`cZ*p`kW^ZzLVRB??Zf5`h00000019wra&2jJEpT*s000000000EaAk6BX>=`hb7gWZa$^7h000000000005bpp01I<-Xf0)AGBq_ZIRF3vAZhB==tO2#AUh_rMLGzKsz6=J#5NtAYAqde990lr-2eapQvd(}3v+X5EoEdfH8n9g0000$74Z7x9c{A9ozu0KKI&lKppMRYt|S_7K}UQ0Bf?aw-06hRfox*&=H!Czutqff40`KrycD3oZ>j(&bdhuo]]]";
        let answer_string_cstr = CString::new(answer_string).unwrap();
        let tmp = Answer::try_from(answer_string);
        assert!(tmp.is_ok());
        let tmp = Answer::try_from(answer_string.to_string());
        assert!(tmp.is_ok());
        let tmp = Answer::try_from(answer_string_cstr.as_c_str());
        assert!(tmp.is_ok());
        assert!(Binary::try_from(tmp.unwrap()).is_ok());
    }

    #[test]
    fn test_challengestring2challenge(){
        let challenge_string = "[[[4UqQ2gDz+Vf_IR`U!gV}^Z)DIoE6{3?4-b<WL(*F]]]";
        let challenge_string_cstr = CString::new(challenge_string).unwrap();
        assert!(Challenge::try_from(challenge_string).is_ok());
        assert!(Challenge::try_from(challenge_string.to_owned()).is_ok());
        assert!(Challenge::try_from(challenge_string).is_ok());
        assert!(Challenge::try_from(challenge_string_cstr.as_c_str()).is_ok());
    }

    #[test]
    fn test_detects_non_matching_key(){
        let private_path_false = PathBuf::from_str("../tests/signed_false").unwrap();
        let cert_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();

        let private_false = load_private_key(&private_path_false).unwrap();
        let certificate = load_certificate(&cert_path).unwrap();
        assert!(private_false.matches(&certificate).is_err());
    }


    macro_rules! signer_signee_combination {
        ($($signee:ident, $signed:ident);* $(;)?) => {
            paste!{
                $(
                    #[test]
                    fn [<$signee _ $signed>]() {
                        let key_folder = PathBuf::from_str("../tests/keys_unlimited/").expect("Folder should be there");
                        let signed_private_path = key_folder.clone().join(stringify!($signed));
                        let _signee_public_path = key_folder.clone().join(format!("{}.pub", stringify!($signee)));
                        let cert_path = key_folder.clone().join(format!("{}-{}.cert", stringify!($signee), stringify!($signed)));

                        println!("Signed private path: {}", fs::canonicalize(&signed_private_path).expect("Private Key should be there").display());
                        println!("Certificate path: {}", fs::canonicalize(&cert_path).expect("Certificate should be there").display());
                        let private_key = load_private_key(&signed_private_path).expect("We already have tests covering the loading of these key, this should work");
                        let cert = load_certificate(&cert_path).expect("We already tested the loading of the key, this should work");
                        println!("Key loading finished");
                        let engine = PrivateKeyAndCertificate {
                            private: private_key,
                            intermediate: cert
                        };
                        println!("Engine created");

                        let challenge = Challenge::new();
                        println!("Challenge created");

                        let answer = engine.generate_answer(&challenge).expect("A answer should always be generated");
                        println!("Answer created");

                        let tmp = answer.to_string();
                        println!("Into string worked");
                        let back = Answer::try_from(tmp);

                        println!("Back and forth also worked");
                        match back{
                            Ok(t) => {
                                //assert_eq!(t.signature.algorithm(), answer.signature.algorithm());
                                assert!(t.signature.as_bytes() == answer.signature.as_bytes());
                                assert!(t.intermediate.algorithm() == answer.intermediate.algorithm());
                                assert!(t.intermediate.signature() == answer.intermediate.signature());
                            }
                            Err(e) => {
                                println!("{} {}: {}", stringify!($signee), stringify!($signed), e);
                                assert!(false);
                            }
                        };
                    }
                )*
            }
        }
    }

    signer_signee_combination!(ecdsa_nistp256, ecdsa_nistp384);
    signer_signee_combination!(ecdsa_nistp256, ecdsa_nistp521);
    signer_signee_combination!(ecdsa_nistp256, ed25519);
    signer_signee_combination!(ecdsa_nistp256, rsa_sha256);
    signer_signee_combination!(ecdsa_nistp256, rsa_sha512);

    signer_signee_combination!(ecdsa_nistp384, ecdsa_nistp256);
    signer_signee_combination!(ecdsa_nistp384, ecdsa_nistp521);
    signer_signee_combination!(ecdsa_nistp384, ed25519);
    signer_signee_combination!(ecdsa_nistp384, rsa_sha256);
    signer_signee_combination!(ecdsa_nistp384, rsa_sha512);

    signer_signee_combination!(ecdsa_nistp521, ecdsa_nistp256);
    signer_signee_combination!(ecdsa_nistp521, ecdsa_nistp384);
    signer_signee_combination!(ecdsa_nistp521, ed25519);
    signer_signee_combination!(ecdsa_nistp521, rsa_sha256);
    signer_signee_combination!(ecdsa_nistp521, rsa_sha512);

    signer_signee_combination!(ed25519, ecdsa_nistp256);
    signer_signee_combination!(ed25519, ecdsa_nistp384);
    signer_signee_combination!(ed25519, ecdsa_nistp521);
    signer_signee_combination!(ed25519, rsa_sha256);
    signer_signee_combination!(ed25519, rsa_sha512);

    signer_signee_combination!(rsa_sha256, ecdsa_nistp256);
    signer_signee_combination!(rsa_sha256, ecdsa_nistp384);
    signer_signee_combination!(rsa_sha256, ecdsa_nistp521);
    signer_signee_combination!(rsa_sha256, ed25519);
    signer_signee_combination!(rsa_sha256, rsa_sha512);

    signer_signee_combination!(rsa_sha512, ecdsa_nistp256);
    signer_signee_combination!(rsa_sha512, ecdsa_nistp384);
    signer_signee_combination!(rsa_sha512, ecdsa_nistp521);
    signer_signee_combination!(rsa_sha512, ed25519);
    signer_signee_combination!(rsa_sha512, rsa_sha256);
}
