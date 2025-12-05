# pam-ttysshca
[![codecov](https://codecov.io/gh/FrederikLauber/pam-ttysshca/graph/badge.svg)](https://codecov.io/gh/FrederikLauber/pam-ttysshca)

**pam-ttysshca** is a PAM module that implements a human-readable challenge–response login mechanism. It is primarily intended for situations where the transport layer can be assumed to be secure—such as a serial connection, local console, or remote control via tools like TeamViewer—and where authentication is traditionally password-based.

Instead of using a static password, this module generates a unique login prompt based on a server-generated challenge. The user must respond with a digital signature, providing a stronger, per-session authentication method.

This is an extension of my previous pam-ed25519 allowing for virtually all encryption mechanisms implemented for ssh.

---

## 🛠️ Usage

The module works like a typical PAM authentication plugin:

1. The server generates a 32-byte random challenge.
2. This challenge is shown to the user, encoded in base85.
3. The user signs the challenge using their private key.
4. The user enters the base85-encoded signature and an intermediate certificate for their public key from the CA as their "password".
5. The PAM module verifies the signature against the intermediate key and the intermediate key against the CA as well as the allowed users.

---

## 🔌 Integration

You can integrate `pam-ttysshca` into any PAM-based service. For example:

### `/etc/pam.d/login`

The allowed CA public keys can be supplied with a ca=/path/to/CA.
Multiple CAs are allowed

---

## 🔐 Authenticators

To generate the Answer to a challenge, this project supplies 3 ways:

1. A CLI.
2. A GUI application.
3. A python library for integration into other systems.

---

## Pam integration and testing

You can integrate this project into your pam system by copying the pam .so file to 
 /lib/security/

Then add it to your pam workflow for example your login

   auth       required   pam_ttysshca.so ca=/lib/test/CA1.pub ca=/lib/test/CA2.pub

afterwards, you can run
pamtester your_workflow your_user authenticate

to test the workflow.

## Python library

To use the python library, build it via cargo build --release -p pypam_ttysshca.
Copy the resulting libpypam_ttysshca.so to your site package folder as pypam_ttysshca.so i.e. /usr/lib/python3.13/site-packages/pypam_ttysshca.so

Then import the module, construct the answer machine to finally create a response like so:

    priv_str = '''-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAg3S091CFgpnwttEeNct6/4ooxBanAET3A8lLvcHDnMgAAAJBebsW4Xm7F\nuAAAAAtzc2gtZWQyNTUxOQAAACAg3S091CFgpnwttEeNct6/4ooxBanAET3A8lLvcHDnMg\nAAAEAPyZL9nMdmHg6ACf6BxSZXXiXoXonH+LLDDMe25xfd7SDdLT3UIWCmfC20R41y3r/i\nijEFqcARPcDyUu9wcOcyAAAACXA5MUBTaGlvbgECAwQ=\n-----END OPENSSH PRIVATE KEY-----'''\n\
    cert_str = 'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIO/QnSgEjvQRbOoGP5DCz//CKKddkaPLyz/GjRJmRu/GAAAAICDdLT3UIWCmfC20R41y3r/iijEFqcARPcDyUu9wcOcyAAAAAAAAAAAAAAABAAAAFHRlc3R1c2VyQGV4YW1wbGUuY29tAAAADAAAAAh0ZXN0dXNlcgAAAABpAr4wAAAAAHvBkqUAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBp6tXoRGZWIDsms0U6CIyqQF3KxDYdnGotHXMcVRBe3QAAAFMAAAALc3NoLWVkMjU1MTkAAABAFfD65B1tssud07WXPupg36COznmuJBpvQUd7+yPCVKrc6YTPgWxi8ebkgu6wRjT9DHrrbbwUoMBvqgAodJF0DQ== p91@Shion'\n\
    challenge_str = '[[[dUHu!9csD2^MlD3Yf_|-sUU}Ut8s25A5Ry6j}}w%]]]'\n\
    expected = '[[[0s:7rC9mWd0t=nRuOOl+>8Swx;;KzD9Sn;qvo$SHmrfapZ<)#)2adM!D3-6AGV**_!-!hoP63$Ntf2940{s:0000Wb8~1dWn?lnH8D9YV`Xx5Ep{+5KyPqmZgX>JE@N+P0000W@6eqn1dj9(Z0ZI-kiyUZ!YHR*k)zAYKgNv`W=8ME0000WAl)rJ)FEJ|d@Zy`jdI?<;)*c^slX9E!17Y>aB$}`0000000000000010000KbY*jNb#rBMKxKGgZE$R5E@N+P0000C00008bY*jNb#rBM00000X#&1500000d%=>W000000001j0000LaAk6BX>=`EF)=M>Z*q5Ga%5?4X8-^I000007jR{AZE18ZVP|D-bS-9Ya(7{JWNB_^000000000MaAk6BX>=`cZ*p`kW^ZzLVRB??Zf5`h00000019wra&2jJEpT*s000000000EaAk6BX>=`hb7gWZa$^7h000000000005bpp01I<-Xf0)AGBq_ZIRF3vAZhB==tO2#AUh_rMLGzKsz6=J#5NtAYAqde990lr-2eapQvd(}3v+X5EoEdfH8n9g0000$74Z7x9c{A9ozu0KKI&lKppMRYt|S_7K}UQ0Bf?aw-06hRfox*&=H!Czutqff40`KrycD3oZ>j(&bdhuo]]]'\n\
    tmp = m.PyPrivateKeyAndCertificate(priv_str, cert_str)\n\
    answer = tmp.generate_answer(challenge_str)\n").unwrap();

## ⚖️ License

All parts of this project are licensed under the GPL3.0.