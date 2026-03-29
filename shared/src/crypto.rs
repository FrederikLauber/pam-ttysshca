use std::ffi::CStr;
use std::fmt;
pub use ssh_key::{Certificate, Fingerprint, HashAlg, PrivateKey, Signature};
use ssh_key::{PublicKey, SshSig};
use ssh_key::encoding::{Decode, Encode};
use crate::binary::{Binary, DisplayBinary, IntoBinary};

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
        let mut signature_bytes = Vec::new();
        let mut certificate_bytes = Vec::new();

        self.signature.encode(&mut signature_bytes)
            .map_err(|_| "Failed to encode signature").map_err(|_| fmt::Error)?;
        self.intermediate.encode(&mut certificate_bytes)
            .map_err(|_| "Failed to encode certificate").map_err(|_| fmt::Error)?;

        write!(f, "{}", Binary(vec![signature_bytes, certificate_bytes]))
    }
}


impl TryFrom<Binary> for Answer {
    type Error = &'static str;

    fn try_from(s: Binary) -> Result<Self, Self::Error> {
        if s.len() != 2 {
            return Err("Expected 2 binary blobs");
        }

        let mut signature_bytes: &[u8] = &s.0[0];
        let mut intermediate_bytes: &[u8] = &s.0[1];


        let signature = ssh_key::Signature::decode(&mut signature_bytes).map_err(|_| "Could not decode signature")?;
        let intermediate = ssh_key::Certificate::decode(&mut intermediate_bytes).map_err(|_| "Could not decode intermediate")?;

        Ok(Answer {
            signature,
            intermediate,
        })
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
        let mut signature_bytes = Vec::new();
        let mut certificate_bytes = Vec::new();

        s.signature.encode(&mut signature_bytes)
            .map_err(|_| "Failed to encode signature")?;
        s.intermediate.encode(&mut certificate_bytes)
            .map_err(|_| "Failed to encode certificate")?;

        let tmp = vec![signature_bytes, certificate_bytes];
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
    use crate::{load_ca, load_certificate, load_private_key, CryptoFileLoadError};
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
        let private = load_private_key(&private_path, None::<&[u8]>).unwrap();
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

        let private_false = load_private_key(&private_path_false, None::<&[u8]>).unwrap();
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

        let private_false = load_private_key(&private_path_false, None::<&[u8]>).unwrap();
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
    fn test_binary2answer_but_not_2_blobs(){
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
        let answer_string = "[[[0000Ca&uuVb7)~QEj2MR0004i702Zc!bS`vLvh4p*-25ks2XsC=p*;GopY~atzGY9j%4uoFf?hcwPSt=j`|DfqaG<NmQ<rzG+L;fYiHhh`RO3J!$uZN2%)$~uwRDyyxh{7M-Ks5sdX?XplJYslMF%)j3_xY>7CuXA46wzqxWXW%}5pxxFSN6YKK(Lf)E1YimzjFDQ2`dnvCEPI`I>B#{@d@?<uIaD#j-hVfcyry!GdwGin}$sQdRxbvXZ>&nk^Tze7aA1Yo}?uD0_EK=}ZoF+uOs$?>@=>U5VkB*hh7j)a_Dr(IleaVn~~zQnj9JCfMQwK4!@4;G<UC_tFoP6HvXr8Ae+{@SCBLtD!^YJht~gTec;-qW=1Z#(PCCwYJ@vXnbtrOsAv6fp6bRQ0bIc><D<`;(O#zIzT(i=iXlH7}odj`${l$9ed?J48+^x#SemG+>KPEyF|cs!2XImfeG0<lPJpBTXI^v_zHIyseffoxGL4J~mqlm*xZuqWW6w:0000Sb8~1da&uuVV`Xx5Ep{+5KyPqmZgX>JE@N+P0000Wen9_7+ArNdaR<(Hs`qAJ<)D&1&ekQX6SJek&)&=o000030RRC200Dsj@L-Bd(h+cZH7^vy`lVn34m8cD+dd6ztz|4{0y_LyFs<0OG-GXtcUhWk&Zj$JQlnly=D1;})+b6VQjggwn6DXg88=DtXTmarIP*%fKSgPd3&TI>W|doiMVWZ;(ZeP#qQiE-*l^NiLi-Eu9LZ(h=Q+Qat(Oy!hrx2tM2ojK%(=sXssE=P_>-u>HOAMui3UzPluqBbX-7u77fa;gqZWqxAQ`P#PB)-6@+t<cAbPD8B~o0H*nxJU0pX(=;P-ya*n4U!VjAe#+If!iNOXO8(ZK^r%9CRsd0rUOc<FL|+kh-T+>dDEoIow%>xiOoH$4U@z>JBBP|ATU{(C+>%bO%?C10LK1~Zx)Po#{td5P?za@_;HK^eH=+0LKJ>}d~KTG+Ix{MfAO7*lAv@baU2i8wf$HIgx2+j5Ca$g`x%F}XLI<f?WGBrHh>Kqwt=``-_qk~z|kAr;+?Y)=mU3e5#yQl#NJS7aO6mAo)s*8(h;0000000000000010000FMsj6jWpZh2AWUI(Vr6mw000O8000DXZ*Oz}0000000030|NsC0|Ns9000000004pj000$mWpZt4bS+phF)e0qa(7{JWNB_^000000000NaAk6BX>=`NXJu}5EoN_WcVTj5X>Ml#00000000(nWpZt4bS-dia&#?bZ*q5Ga%5?4X8-^I000003UFm|ZE18ZaCCV900000000hfWpZt4bS-srWpXWYV*mgE00000000027XSbN2Xk|1Epl^V000030RRC200IF3%O;)j7NYBIXxNWp2#wddHr~eq%>3voSP<A?%@%$C7}`ZM;}d)TQ!qa8@;YE*8{@s&%E4g}W`Rk+<i=aA^_)ypMH*$fAkw7evh9~E+%iyE0=z><_*`?Q+OnIZ?z*AfH7z?F7{a@Piv=E_<wqvVKDCtFNF32;L4W_})perU)wy6tx&P@pds7BIXe5qJhdyr*X=WF9>30f8VyW`kQ^)j`5la%G1S*+(8s^@S<q<BGrzGIb4CV2nEv{xK_$Y*F@j|g-I6ClXIgZ^HT180vKLG^h|G*DKt28<v3m|#T^LbMyk;e-kZ0t2A=V};L42+qVQ11>|SJ<9G2LLB}SCSzomr|R~1E^{nq7_j<V)RDvkQ=)re_pBt<O?il`d^>o*6Z5Y8#9!#PRcSC<|ijE?Vz%8eT~&TWgOkxL;%wdsw#2vX+M~p52~U)!?vRVxU-dS-bn4Sk9v{ijnc6}>e<#MOZ$|%93y0u#kno8&_~>K&m%}+QXxxU5!7Ie@rs91Ut0^$IHg-PgKyIbWKsN$9xSt>WZ7~v)ud1!kW=Y|URn+xbbXOL9rEFyl5QACOu{4CCfOQ*ZuAr)>@u@ify(#3U}0aEa1%H;=Xewu!2@F&nG$)DKjk^6Rj=x|9g@Mv^k=h&H1&^BKw=Gb0006M0000Ca&uuVb7)~QEj2MR00062AbfC9L%`A$y+9IJ!sXEHy>~I+G{Va0!xk-46(eO;pyr>z(6B(a_kU+c1dxA(RQt@jjN#Yh^;+0PNHqOw#PdALJLvFNCz9MZxwLOa3%NN{VBxvF0HPi22i-V+8d6-Mvs95Y3OY|s8)-vj%Hh_fpsL9#K)RLc^1!@EO=>YMLAzYPj&!9M^Gj;w<40$_dE<Nasau6>$Bscc?9p0my!BI)p6A#1t#=0AE6?sT)kADlMD^vKP?cVy=al%8Li2}ZTrpSbVm7x9Cu+{`gKzqSAq=JUCy+od+)`XmFuXYP{{d$(aN<@G29@(luX2P{4@?|1Hp%?HGFBuN8BBFmQ+UgJB9HocARbFh`4ibBYJIqwe}6hRWMHTa?I?!Zxu!!Bu0>gAycIPEi17N|lBs1)xyLko*ek>dwS5gm68|5VJ}LKxg(npMgq`To9$6|iYbBbm@GBDWHwz+~<HE@ugrQ9#xvBq}C5%<jplDm%nrwy-1N>my%a%H&yeZM&ru4xjF2dtHjeKqg+9ij2=+KK_v?4FMsiE7${j(@&)g3w1=NXS*8wkX<tOGsB6D0%I<eBJ^5T2V)Sk!E-1NUFQhf96hpycHZ=9gfej#0*u`2-(C14wJ2l)NCS6$+*ie}~j4JCJRWo_!|2gpTiG]]]";
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

        let private_false = load_private_key(&private_path_false, None::<&[u8]>).unwrap();
        let certificate = load_certificate(&cert_path).unwrap();
        assert!(private_false.matches(&certificate).is_err());
    }

    #[test]
    fn test_encrypted_key(){
        let private_path_false = PathBuf::from_str("../tests/signed_encrypted").unwrap();
        let cert_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();

        let private_false = load_private_key(&private_path_false, Some("test")).unwrap();
        let certificate = load_certificate(&cert_path).unwrap();
        assert!(private_false.matches(&certificate).is_ok());
    }

    #[test]
    fn test_encrypted_key_wrong_password(){
        let private_path_false = PathBuf::from_str("../tests/signed_encrypted").unwrap();
        let failed_privatekey = load_private_key(&private_path_false, Some("test2"));
        assert!(failed_privatekey.is_err());
        assert!(failed_privatekey.is_err_and(|x| matches!(x, CryptoFileLoadError::CouldNotLoadPrivateFileWithPassword(_))));
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
                        let private_key = load_private_key(&signed_private_path, None::<&[u8]>).expect("We already have tests covering the loading of these key, this should work");
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
