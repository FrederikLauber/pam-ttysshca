#![cfg(target_os = "linux")]

extern crate pam;

use std::ffi::CStr;
use std::path::PathBuf;
use shared::{Answer, Challenge, load_ca};
use syslog::{Facility, Formatter3164};

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

fn args2fingerprints(args: Vec<&CStr>) -> Vec<Fingerprint> {
    let mut trusted_certs = Vec::new();

    for arg_cstr in args {
        if let Ok(arg) = arg_cstr.to_str() {
            if let Some(rest) = arg.strip_prefix("ca=") {
                let ca_path = PathBuf::from(rest);
                syslog(format!("Loading: `{}`", rest).as_str());

                if let Ok(cert) = load_ca(&ca_path) {
                    trusted_certs.push(cert.fingerprint(Default::default()));
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
    return trusted_certs;
}

impl PamContext for PamHandle {
    fn username(&self) -> Result<String, PamResult> {
        &self.get_user().ok_or(PAM_ABORT)
    }
    
    fn get_response(&self, challenge: &Challenge) -> Result<Answer, PamResult> {
        &self.info(&format!("pam-ttysshca Challenge: {}\n", challenge)).map_err(|_| PAM_ABORT)?;
        let response_cstr = &self.prompt(PAM_PROMPT_ECHO_ON, "Response: ").map_err(|_| PAM_ABORT)?;
        Answer::try_from(response_cstr).map_err(|_| PAM_AUTH_ERR)
    }
}

fn authenticate<T: PamContext>(ctx: &T, args: &[&CStr]) ->PamResult {
    let username = ctx.username()?;
    let challenge = Challenge::new();
    
    let answer = ctx.get_response(challenge)?;

    let _ = answer.verify_signature(&challenge).map_err(|_| PAM_AUTH_ERR)?;

    let trusted_certs = args2fingerprints(args);
    
    if let Err(e) = answer.verify_intermediate(&trusted_certs, username){
        syslog(e);
        PAM_AUTH_ERR
    } else {
        PAM_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(pamh: *mut PamHandle, args: *mut *const i8, argc: i32) -> i32 {
    let (pamh, args) = unsafe {
        let pamh = PamHandle::from_ptr(pamh);
        let args: Vec<&CStr> = (0..argc)
            .map(|i| CStr::from_ptr(*args.offset(i as isize)))
            .collect();

        (pamh, args)
    };
    authenticate(&pamh, &args)
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(_pamh: *mut PamHandle, _flags: i32) -> i32 {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::str::FromStr;
    use shared::{load_certificate, load_private_key, AnswerEngine, PrivateKeyAndCertificate};
    use super::*;

    #[test]
    fn test_incorrect_response(){
        let challenge = Challenge::new();
        let user = "tesuser";

        // just some random bytes for testing
        let answer = CString::new([86, 235, 98, 201, 205, 180, 24, 232, 218, 79, 226, 20, 185, 128, 148, 207, 38, 62, 13, 177, 30, 250, 1, 28, 157, 132, 109, 190, 185, 161, 63, 180]).unwrap();
        let mut args = Vec::new();

        let ca1 = CString::from_str("ca=Ca1.pub").unwrap();
        let ca2 = CString::from_str("ca=Ca2.pub").unwrap();

        args.push(ca1.as_ref());
        args.push(ca2.as_ref());

        assert!(! correct_response(answer.as_ref(), args, user, challenge));
    }

    #[test]
    fn test_correct_response(){
        let challenge = Challenge::new();
        let user = "testuser";

        let priv_path = PathBuf::from("../tests/signed");
        let cert_path = PathBuf::from("../tests/signed-cert.pub");
        let ca = PathBuf::from("../tests/CAs/ca1.pub").canonicalize().expect("We should see the file here");

        let private = load_private_key(&priv_path).expect("Tested keys and path should load");
        let cert = load_certificate(&cert_path).expect("Tested keys and paths should load");
        let answer_engine = PrivateKeyAndCertificate::new(private, cert).unwrap();

        let answer = answer_engine.generate_answer(&challenge).expect("Tested keys should generate a answer");

        let mut args = Vec::new();

        let ca1_path = format!("ca={}", ca.display());
        let ca1 = CString::from_str(&ca1_path).expect("This should be a valid CString");

        args.push(ca1.as_ref());

        let answer_str = format!("{}", answer);
        let answer_cstr = CString::new(answer_str).unwrap();

        assert!(correct_response(&answer_cstr, args, user, challenge));

    }

    #[test]
    fn test_all_correct_but_not_from_ca(){
        let challenge = Challenge::new();
        let user = "testuser";

        let priv_path = PathBuf::from("../tests/signed");
        let cert_path = PathBuf::from("../tests/signed-cert.pub");
        let ca = PathBuf::from("../tests/CAs/ca2.pub").canonicalize().expect("We should see the file here");

        let private = load_private_key(&priv_path).expect("Tested keys and path should load");
        let cert = load_certificate(&cert_path).expect("Tested keys and paths should load");
        let answer_engine = PrivateKeyAndCertificate::new(private, cert).unwrap();

        let answer = answer_engine.generate_answer(&challenge).expect("Tested keys should generate a answer");

        let mut args = Vec::new();

        let ca1_path = format!("ca={}", ca.display());
        let ca1 = CString::from_str(&ca1_path).expect("This should be a valid CString");

        args.push(ca1.as_ref());

        let answer_str = format!("{}", answer);
        let answer_cstr = CString::new(answer_str).unwrap();

        assert!(! correct_response(&answer_cstr, args, user, challenge));

    }
}
