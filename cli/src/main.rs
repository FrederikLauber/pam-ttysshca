use std::io;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use clap::{Parser};
use shared::{load_private_key, load_certificate, Challenge, AnswerEngine, PrivateKeyAndCertificate};

#[derive(Parser)]
#[command(about = "CLI Authenticator", long_about = None)]
struct Cli {
    private_key: PathBuf,
    certificate: PathBuf,
}
fn inner_logic<R: BufRead, W: Write>(cli: &Cli, mut input: R, mut output: W) {
    let private_key = load_private_key(&cli.private_key).unwrap();
    let certificate = load_certificate(&cli.certificate).unwrap();
    let answer_engine = PrivateKeyAndCertificate::new(private_key, certificate).unwrap();

    loop {
        write!(output, "Input challenge:").unwrap();
        let mut line = String::new();
        if let Ok(t) = input.read_line(&mut line) {
            if t == 0 { break; }
        } else {
            break;
        }

        if line.trim().starts_with("q"){
            break;
        }

        let challenge = Challenge::try_from(line).unwrap();
        let answer = answer_engine.generate_answer(&challenge).unwrap();
        writeln!(output, "Answer: {}", answer).unwrap();
    }
}

fn main() {
    inner_logic(&Cli::parse(), io::stdin().lock(), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};
    use super::*;

    #[test]
    fn cli_inner_logic() {
        let priv_path = PathBuf::from("../tests/signed");
        let cert_path = PathBuf::from("../tests/signed-cert.pub");

        let challenge_str = "[[[dUHu!9csD2^MlD3Yf_|-sUU}Ut8s25A5Ry6j}}w%]]]\nq\n";
        let answer_str = "[[[0R:7rC9mWd0t=nRuOOl+>8Swx;;KzD9Sn;qvo$SHmrfapZ<)#)2adM!D3-6AGV**_!-!hoP63$Ntf2940{s:0000Wb8~1dWn?lnH8D9YV`Xx5Ep{+5KyPqmZgX>JE@N+P0000W@6eqn1dj9(Z0ZI-kiyUZ!YHR*k)zAYKgNv`W=8ME0000WAl)rJ)FEJ|d@Zy`jdI?<;)*c^slX9E!17Y>aB$}`0000000000000010000KbY*jNb#rBMKxKGgZE$R5E@N+P0000C00008bY*jNb#rBM00000X#&1500000d%=>W000000001j0000LaAk6BX>=`EF)=M>Z*q5Ga%5?4X8-^I000007jR{AZE18ZVP|D-bS-9Ya(7{JWNB_^000000000MaAk6BX>=`cZ*p`kW^ZzLVRB??Zf5`h00000019wra&2jJEpT*s000000000EaAk6BX>=`hb7gWZa$^7h000000000005bpp01I<-Xf0)AGBq_ZIRF3vAZhB==tO2#AUh_rMLGzKsz6=J#5NtAYAqde990lr-2eapQvd(}3v+X5EoEdfH8n9g0000$74Z7x9c{A9ozu0KKI&lKppMRYt|S_7K}UQ0Bf?aw-06hRfox*&=H!Czutqff40`KrycD3oZ>j(&bdhuo]]]";
        let cli = Cli {
            private_key: priv_path,
            certificate: cert_path
        };

        let reader = BufReader::new(&challenge_str.as_bytes()[..]);

        let mut output = Vec::new();

        inner_logic(&cli, reader, &mut output);
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains(answer_str));
        // empty reader
        let reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let mut output = Vec::new();
        inner_logic(&cli, reader, &mut output);
    }
}