use std::process::Command;
use {
    std::{
        io,
    },
};

#[cfg(windows)]
fn set_windows_icon() -> io::Result<()> {
    use winresource::WindowsResource;
    WindowsResource::new()
        .set_icon("../assets/Authenticator.ico")
        .compile()
}

#[cfg(not(windows))]
fn set_windows_icon() -> io::Result<()> {
    // No-op on non-Windows platforms
    Ok(())
}

fn main() -> io::Result<()> {
    let _ = set_windows_icon();

    let output = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .expect("Failed to execute git");

    let git_tag = String::from_utf8(output.stdout).expect("Invalid UTF-8 in git output");
    let git_tag = git_tag.trim();

    println!("cargo:rustc-env=GIT_TAG={}", git_tag);
    
    Ok(())
}