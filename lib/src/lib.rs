#![cfg(target_os = "linux")]

extern crate pam;

use std::ffi::CStr;
use std::path::PathBuf;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use shared::{Answer, Challenge, load_ca};
use syslog::{Facility, Formatter3164};

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

fn correct_response(response_cstr: &CStr, args: Vec<&CStr>, username: &str, challenge: Challenge) -> bool {
        let answer = match Answer::try_from(response_cstr) {
            Ok(a) => a,
            Err(_) => {return false}
        };

        if let Err(_) = answer.verify_signature(&challenge) {
            return false;
        }

        let mut trusted_certs = Vec::new();

        syslog("starting to parse args");

        for arg_cstr in &args {
            if let Ok(arg) = arg_cstr.to_str() {
                syslog(format!("Arg: `{}`", arg).as_str());

                if let Some(rest) = arg.strip_prefix("ca=") {
                    let ca_path = PathBuf::from(rest);
                    if let Ok(cert) = load_ca(&ca_path) {
                        trusted_certs.push(cert.fingerprint(Default::default()));
                    } else {
                        syslog(format!("Could not load CA `{}`", rest).as_str());
                    }
                }
            } else {
                syslog("Invalid UTF-8 in C string");
            }
        }

        if let Ok(_) = answer.verify_intermediate(&trusted_certs, username){
            true
        } else {
            false
        }

}


impl PamHooks for Pamttysshca {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode  {
        syslog("Start");

        let username = match pam_try!(pamh.get_item::<pam::items::User>()) {
            Some(e) =>
                match e.0.to_str() {
                    Ok(u) => u,
                    Err(_) => {return PamResultCode::PAM_ABORT;}
                },
            None => {return PamResultCode::PAM_ABORT;}
        };

        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            _ => { return PamResultCode::PAM_ABORT; }
        };

        let challenge = Challenge::new();
        let _ = conv.send(pam::constants::PAM_TEXT_INFO, &format!("pam-ttysshca Challenge: {}\n", challenge));
        // Now prompt for the response
        let response_cstr = match pam_try!(conv.send(PAM_PROMPT_ECHO_ON, "Response: ")) {
            Some(response) => response,
            None => {
                return PamResultCode::PAM_ABORT;
            },
        };

        if correct_response(response_cstr, args, username, challenge){
            PamResultCode::PAM_SUCCESS
        } else {
            PamResultCode::PAM_AUTH_ERR
        }
    }
}


#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::str::FromStr;
    use super::*;

    #[test]
    fn test_correct_response(){
        let challenge = Challenge::new();
        let user = "tesuser";

        // just some random bytes for testing
        let answer = CString::new([86, 235, 98, 201, 205, 180, 24, 232, 218, 79, 226, 20, 185, 128, 148, 207, 38, 62, 13, 177, 30, 250, 1, 28, 157, 132, 109, 190, 185, 161, 63, 180]).unwrap();
        let mut args = Vec::new();

        let ca1 = CString::from_str("ca=Ca1.pub").unwrap();
        let ca2 = CString::from_str("ca=Ca2.pub").unwrap();

        args.push(ca1.as_ref());
        args.push(ca2.as_ref());

        let _ = correct_response(answer.as_ref(), args, user, challenge);

    }
}
