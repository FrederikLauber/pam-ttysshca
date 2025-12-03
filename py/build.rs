use std::process::Command;

fn main() {
    let output = Command::new("python3")
        .arg("-c")
        .arg("import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        .output()
        .expect("Failed to run python3");

    let version = String::from_utf8(output.stdout).unwrap();
    let version = version.trim();

    println!("cargo:rustc-link-lib=dylib=python{}", version);
    println!("cargo:rustc-link-search=native=/usr/lib");
}
