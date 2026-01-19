#![cfg(target_os = "linux")]
extern crate pam;

use std::ffi::CStr;
use std::path::PathBuf;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use shared::{Answer, Challenge, load_ca, Fingerprint};
use syslog::{Facility, Formatter3164};
use ssh_key::authorized_keys::AuthorizedKeys;

struct Pamttysshca;
pam::pam_hooks!(Pamttysshca);

fn syslog(msg: &str){
    // build syslog so log macro works
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: "pam-ttysshca".into(),
        pid: std::process::id() as u32,
    };

    let mut logger = syslog::unix(formatter).ok();

    match &mut logger{
        Some(e) => {let _ = e.info(msg);},
        None => {}
    }
}

fn args2fingerprints(args: Vec<&CStr>) -> Vec<Fingerprint>{
    let mut trusted_certs = Vec::new();

    for arg_cstr in args {
        if let Ok(arg) = arg_cstr.to_str() {
            if let Some(rest) = arg.strip_prefix("ca=") {
                let ca_path = PathBuf::from(rest);
                syslog(format!("Loading: `{}`", rest).as_str());

                if let Ok(certs) = AuthorizedKeys::read_file(&ca_path){
                    for cert in certs {
                        trusted_certs.push(cert.fingerprint(Default::default()));
                    }
                } else {
                    syslog(format!("Could not load CA `{}`", rest).as_str());
                }
            } else {
                syslog(format!("Unsupported argument `{}`", arg).as_str());
            }
        } else {
            syslog("Invalid UTF-8 in C string");
        }
    }
    trusted_certs
}

trait PamContext {
    fn post_challenge_and_get_response(&self, challenge:  &Challenge) -> Result<Answer, PamResultCode>;
}


impl PamContext for PamHandle {
    fn post_challenge_and_get_response(&self, challenge: &Challenge, ) -> Result<Answer, PamResultCode> {
        let conv = self
            .get_item::<Conv>()
            .ok()
            .flatten()
            .ok_or(PamResultCode::PAM_ABORT)?;

        conv.send(
            pam::constants::PAM_TEXT_INFO,
            &format!("pam-ttysshca Challenge: {}\n", challenge),
        ).map_err(|_| PamResultCode::PAM_ABORT)?;

        let userinput = conv.send(PAM_PROMPT_ECHO_ON, "Response: ")
            .ok()
            .flatten()
            .ok_or(PamResultCode::PAM_AUTH_ERR)?;

        Answer::try_from(userinput).map_err(|_| PamResultCode::PAM_AUTH_ERR)
    }
}

fn authenticate<T: PamContext>(ctx: &T, args: Vec<&CStr>, username: &str) -> PamResultCode {
    let challenge = Challenge::new();
    syslog("Posting challenge");
    let answer = pam_try!(ctx.post_challenge_and_get_response(&challenge));
    syslog("Answer received, starting validation");

    if let Err(_) = answer.verify_signature(&challenge) {
        syslog("Signature verification failed");
        return PamResultCode::PAM_AUTH_ERR;
    }

    let trusted_certs = args2fingerprints(args);

    if let Err(e) = answer.verify_intermediate(&trusted_certs, &username){
        syslog(e);
        PamResultCode::PAM_AUTH_ERR
    } else {
        PamResultCode::PAM_SUCCESS
    }
}

impl PamHooks for Pamttysshca {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        if let Some(user) = pamh.get_item::<pam::items::User>().ok().flatten() {
            if let Ok(username) = user.0.to_str() {
                return authenticate(pamh, args, username);
            }
        }
        PamResultCode::PAM_ABORT
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::str::FromStr;
    use shared::{load_certificate, load_private_key, AnswerEngine, PrivateKeyAndCertificate};
    use super::*;

    struct MockPamHandlerSuccess;
    struct MockPamHandlerFailure1;
    struct MockPamHandlerFailure2;
    struct MockPamHandlerFailure3;


    impl PamContext for MockPamHandlerSuccess{
        fn post_challenge_and_get_response(&self, challenge:  &Challenge) -> Result<Answer, PamResultCode>{
            let private_path = PathBuf::from_str("../tests/signed").unwrap();
            let cert_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();

            let private = load_private_key(&private_path).unwrap();
            let certificate = load_certificate(&cert_path).unwrap();

            let engine = PrivateKeyAndCertificate::new(private, certificate).unwrap();
            let answer = engine.generate_answer(challenge).unwrap();
            Ok(answer)
        }
    }

    impl PamContext for MockPamHandlerFailure1{
        fn post_challenge_and_get_response(&self, challenge:  &Challenge) -> Result<Answer, PamResultCode>{
            let private_path = PathBuf::from_str("../tests/signed_false").unwrap();
            let cert_path = PathBuf::from_str("../tests/signed_false-cert.pub").unwrap();

            let private = load_private_key(&private_path).unwrap();
            let certificate = load_certificate(&cert_path).unwrap();

            let engine = PrivateKeyAndCertificate::new(private, certificate).unwrap();
            let answer = engine.generate_answer(challenge).unwrap();
            Ok(answer)
        }
    }

    impl PamContext for MockPamHandlerFailure2{
        fn post_challenge_and_get_response(&self, challenge:  &Challenge) -> Result<Answer, PamResultCode>{
            let challenge = Challenge::new();

            let private_path = PathBuf::from_str("../tests/signed_false").unwrap();
            let cert_path = PathBuf::from_str("../tests/signed_false-cert.pub").unwrap();

            let private = load_private_key(&private_path).unwrap();
            let certificate = load_certificate(&cert_path).unwrap();

            let engine = PrivateKeyAndCertificate::new(private, certificate).unwrap();
            let answer = engine.generate_answer(&challenge).unwrap();
            Ok(answer)
        }
    }

    impl PamContext for MockPamHandlerFailure3{
        fn post_challenge_and_get_response(&self, challenge:  &Challenge) -> Result<Answer, PamResultCode>{
            let private_path = PathBuf::from_str("../tests/signed").unwrap();
            let cert_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();

            let private = load_private_key(&private_path).unwrap();
            let certificate = load_certificate(&cert_path).unwrap();

            let engine = PrivateKeyAndCertificate::new(private, certificate).unwrap();
            let answer = engine.generate_answer(challenge).unwrap();

            let cert_path_fake = PathBuf::from_str("../tests/signed_false-cert.pub").unwrap();
            let certificate_false = load_certificate(&cert_path_fake).unwrap();
            let faked_answer = Answer{signature: answer.signature, intermediate: certificate_false};
            Ok(faked_answer)
        }
    }


    #[test]
    fn test_correct_response(){
        let user = "testuser";

        // just some random bytes for testing
        let mut args = Vec::new();

        let ca1 = CString::from_str("ca=../tests/CAs/ca1.pub").unwrap();
        let ca2 = CString::from_str("ca=CA_does_not_exist.pub").unwrap();

        args.push(ca1.as_ref());
        args.push(ca2.as_ref());

        let ctx = MockPamHandlerSuccess;
        assert_eq!(authenticate(&ctx, args, user), PamResultCode::PAM_SUCCESS);
    }

    #[test]
    fn test_non_matching_signature(){
        let user = "testuser";

        // just some random bytes for testing
        let mut args = Vec::new();

        let ca1 = CString::from_str("ca=../tests/CAs/ca1.pub").unwrap();
        let ca2 = CString::from_str("ca=CA_does_not_exist.pub").unwrap();

        args.push(ca1.as_ref());
        args.push(ca2.as_ref());

        let ctx = MockPamHandlerFailure1;
        assert_eq!(authenticate(&ctx, args, user), PamResultCode::PAM_AUTH_ERR);
    }


    #[test]
    fn test_incorrect_response(){
        let user = "testuser";

        // just some random bytes for testing
        let mut args = Vec::new();

        let ca1 = CString::from_str("ca=../tests/CAs/ca1.pub").unwrap();

        args.push(ca1.as_ref());

        let ctx = MockPamHandlerFailure2;
        assert_eq!(authenticate(&ctx, args, user), PamResultCode::PAM_AUTH_ERR);
    }

    #[test]
    fn test_non_matching_intermediate(){
        let user = "testuser";

        // just some random bytes for testing
        let mut args = Vec::new();

        let ca1 = CString::from_str("ca=../tests/CAs/ca1.pub").unwrap();
        let ca2 = CString::from_str("ca=CA_does_not_exist.pub").unwrap();

        args.push(ca1.as_ref());
        args.push(ca2.as_ref());

        let ctx = MockPamHandlerFailure3;
        assert_eq!(authenticate(&ctx, args, user), PamResultCode::PAM_AUTH_ERR);
    }


    #[test]
    fn test_non_utf8_in_arguments(){
        let mut args = Vec::new();

        let bytes = vec![0xE2, 0x28, 0xA1]; // invalid UTF-8
        let cstr = CString::new(bytes).unwrap();

        args.push(cstr.as_c_str());
        args2fingerprints(args);
    }

    #[test]
    fn test_non_supported_argument(){
        let mut args = Vec::new();

        let ca1 = CString::from_str("TESTTESTTEST").unwrap();

        args.push(ca1.as_ref());
        args2fingerprints(args);
    }
}
