# pam-ttysshca
![Coverage](https://FrederikLauber.github.io/pam-ttysshca/coverage.svg)

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

## Limitations

This software mostly uses the functionality provided by the ssh_key crate, currently in version 0.7.0-rc4.
Due to this, there are some limitations in key algorithms that can be used most notable 

- rsa256 and rsa512 does not work

Most of these should be fixed as of release 0.7.0 in the near future.

## ⚖️ License

All parts of this project are licensed under the GPL3.0.