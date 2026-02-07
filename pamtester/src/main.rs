use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::ptr;
use std::str::FromStr;
use shared::{load_certificate, load_private_key, AnswerEngine, Challenge, PrivateKeyAndCertificate};

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(
        num_msg: c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conv: *const PamConv,
        pamh: *mut *mut c_void,
    ) -> c_int;

    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
}

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    _appdata_ptr: *mut c_void,
) -> c_int {
    unsafe {
        let replies = libc::calloc(
            num_msg as usize,
            std::mem::size_of::<PamResponse>(),
        ) as *mut PamResponse;

        if replies.is_null() {
            return 1;
        }

        let mut challenge_strings: Vec<String> = Vec::new();
        for i in 0..num_msg {
            let m_ptr = *msg.add(i as usize);
            let m = &*m_ptr;

            let text = if !m.msg.is_null() {
                CStr::from_ptr(m.msg).to_string_lossy()
            } else {
                "".into()
            };

            let response = match m.msg_style {
                PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => {
                    format!("{}", &text)
                }
                _ => String::new(),
            };
            challenge_strings.push(response);
        };

        let challenge = challenge_strings.join("\n");
        let answer = compute_response(&*challenge);

        let c_resp = CString::new(answer).unwrap();
        (*replies.add(0usize)).resp = c_resp.into_raw();
        (*replies.add(0usize)).resp_retcode = 0;

        *resp = replies;
        PAM_SUCCESS
    }
}

fn compute_response(challenge_str: &str) -> String {
    println!("Challenge: {}", challenge_str);
    let private_path = PathBuf::from_str("./tests/signed").unwrap();
    let cert_path = PathBuf::from_str("./tests/signed-cert.pub").unwrap();

    let private = load_private_key(&private_path).unwrap();
    let certificate = load_certificate(&cert_path).unwrap();

    let engine = PrivateKeyAndCertificate::new(private, certificate).unwrap();
    let challenge = Challenge::try_from(challenge_str).unwrap();
    let answer = engine.generate_answer(&challenge).unwrap();

    format!("{}", answer)
}

fn main() {
    let service = CString::new("testauth").unwrap();
    let user = CString::new("testuser").unwrap();

    let mut pamh: *mut c_void = ptr::null_mut();

    let conv = PamConv {
        conv: conversation,
        appdata_ptr: ptr::null_mut(),
    };

    let ret = unsafe {
        pam_start(
            service.as_ptr(),
            user.as_ptr(),
            &conv,
            &mut pamh,
        )
    };

    if ret != PAM_SUCCESS {
        panic!("pam_start failed");
    }

    let ret = unsafe { pam_authenticate(pamh, 0) };
    if ret != PAM_SUCCESS {
        unsafe { pam_end(pamh, ret) };
        panic!("authentication failed");
    }

    let ret = unsafe { pam_acct_mgmt(pamh, 0) };
    if ret != PAM_SUCCESS {
        unsafe { pam_end(pamh, ret) };
        panic!("account check failed");
    }

    unsafe { pam_end(pamh, PAM_SUCCESS) };
    println!("Login successful");
}
