use shared::AnswerEngine;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use shared::{PrivateKeyAndCertificate, PrivateKey, Certificate, Challenge, Binary};

#[pyclass]
pub struct PyPrivateKeyAndCertificate {
    engine: PrivateKeyAndCertificate,
}

#[pymethods]
impl PyPrivateKeyAndCertificate {
    #[new]
    fn new(private_key_openssh: &str, certificate_openssh: &str) -> PyResult<Self> {
        let private_key = PrivateKey::from_openssh(private_key_openssh).map_err(|_| PyRuntimeError::new_err("Private keys could not be parsed"))?;
        let certificate = Certificate::from_openssh(certificate_openssh).map_err(|_| PyRuntimeError::new_err("Certificate could not be parsed"))?;
        let tmp = PrivateKeyAndCertificate::new(private_key, certificate).map_err(|_| PyRuntimeError::new_err("Answer engine could not be created"))?;
        Ok(PyPrivateKeyAndCertificate {engine: tmp})
    }

    fn generate_answer(&self, challenge: &str) -> PyResult<String> {
        let binary = Binary::try_from(challenge).map_err(|_| PyRuntimeError::new_err("Challenge could not be parsed"))?;
        let challenge_ = Challenge::try_from(binary).map_err(|_| PyRuntimeError::new_err("Challenge could not be parsed"))?;
        let answer = self.engine.generate_answer(&challenge_).map_err(|_| PyRuntimeError::new_err("Answer could not be generated"))?;
        Ok(answer.to_string())
    }
}

#[pymodule]
fn pypam_ttysshca(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPrivateKeyAndCertificate>()?;
    Ok(())
}



#[cfg(test)]
mod tests {
    use std::ffi::{CString};
    use pyo3::prelude::*;
    use pyo3::types::IntoPyDict;
    use super::*;

    #[test]
    fn test_my_wrapper() {
        Python::attach(|py| {
            let m = PyModule::new(py, "test").unwrap();

            pypam_ttysshca(&m).unwrap();

            let code = CString::new("assert hasattr(m, 'PyPrivateKeyAndCertificate')\n\
            priv_str = '''-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAg3S091CFgpnwttEeNct6/4ooxBanAET3A8lLvcHDnMgAAAJBebsW4Xm7F\nuAAAAAtzc2gtZWQyNTUxOQAAACAg3S091CFgpnwttEeNct6/4ooxBanAET3A8lLvcHDnMg\nAAAEAPyZL9nMdmHg6ACf6BxSZXXiXoXonH+LLDDMe25xfd7SDdLT3UIWCmfC20R41y3r/i\nijEFqcARPcDyUu9wcOcyAAAACXA5MUBTaGlvbgECAwQ=\n-----END OPENSSH PRIVATE KEY-----'''\n\
            cert_str = 'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIO/QnSgEjvQRbOoGP5DCz//CKKddkaPLyz/GjRJmRu/GAAAAICDdLT3UIWCmfC20R41y3r/iijEFqcARPcDyUu9wcOcyAAAAAAAAAAAAAAABAAAAFHRlc3R1c2VyQGV4YW1wbGUuY29tAAAADAAAAAh0ZXN0dXNlcgAAAABpAr4wAAAAAHvBkqUAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBp6tXoRGZWIDsms0U6CIyqQF3KxDYdnGotHXMcVRBe3QAAAFMAAAALc3NoLWVkMjU1MTkAAABAFfD65B1tssud07WXPupg36COznmuJBpvQUd7+yPCVKrc6YTPgWxi8ebkgu6wRjT9DHrrbbwUoMBvqgAodJF0DQ== p91@Shion'\n\
            challenge_str = '[[[dUHu!9csD2^MlD3Yf_|-sUU}Ut8s25A5Ry6j}}w%]]]'\n\
            expected = '[[[0s:7rC9mWd0t=nRuOOl+>8Swx;;KzD9Sn;qvo$SHmrfapZ<)#)2adM!D3-6AGV**_!-!hoP63$Ntf2940{s:0000Wb8~1dWn?lnH8D9YV`Xx5Ep{+5KyPqmZgX>JE@N+P0000W@6eqn1dj9(Z0ZI-kiyUZ!YHR*k)zAYKgNv`W=8ME0000WAl)rJ)FEJ|d@Zy`jdI?<;)*c^slX9E!17Y>aB$}`0000000000000010000KbY*jNb#rBMKxKGgZE$R5E@N+P0000C00008bY*jNb#rBM00000X#&1500000d%=>W000000001j0000LaAk6BX>=`EF)=M>Z*q5Ga%5?4X8-^I000007jR{AZE18ZVP|D-bS-9Ya(7{JWNB_^000000000MaAk6BX>=`cZ*p`kW^ZzLVRB??Zf5`h00000019wra&2jJEpT*s000000000EaAk6BX>=`hb7gWZa$^7h000000000005bpp01I<-Xf0)AGBq_ZIRF3vAZhB==tO2#AUh_rMLGzKsz6=J#5NtAYAqde990lr-2eapQvd(}3v+X5EoEdfH8n9g0000$74Z7x9c{A9ozu0KKI&lKppMRYt|S_7K}UQ0Bf?aw-06hRfox*&=H!Czutqff40`KrycD3oZ>j(&bdhuo]]]'\n\
            tmp = m.PyPrivateKeyAndCertificate(priv_str, cert_str)\n\
            answer = tmp.generate_answer(challenge_str)\n").unwrap();
            let tmp = [("m", m)].into_py_dict(py).unwrap();

            py.run(
                code.as_c_str(),
                    Some(&tmp),
                    None
                ).unwrap();
            });
    }}