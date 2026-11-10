//! The `RUSTC_WRAPPER` of the profile-guided builds (.github/workflows/release.yml): runs rustc as
//! cargo gives it, passes its output on, and adds what it says about the profile to the file
//! `RUSTC_PGO_LOG` names. rustc only warns when the profile can't be read or doesn't match the
//! code, and builds on without it; pgo-check.sh then fails on them. Not the lines of autocfg's
//! probes, which some build scripts compile: they aren't part of the wheel, and were never trained.
//! A program, not a script, as cargo runs it itself, which on Windows can't be a shell script.
//! pgo-merge.sh builds it, with the job's own rustc.

use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::process::{Command, ExitCode, Stdio};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("rustc-pgo: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<ExitCode> {
    let mut args = env::args_os().skip(1);
    let rustc = args
        .next()
        .ok_or_else(|| io::Error::other("usage: rustc_pgo RUSTC [ARG]..."))?;
    let log =
        env::var_os("RUSTC_PGO_LOG").ok_or_else(|| io::Error::other("RUSTC_PGO_LOG isn't set"))?;
    let output = Command::new(rustc)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .output()?;
    io::stderr().write_all(&output.stderr)?;

    let mut about_profile = String::new();
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        let about = ["hash mismatch", "profile data", ".profdata"]
            .iter()
            .any(|s| line.contains(s));
        if about && !line.contains("autocfg_") {
            about_profile.push_str(line);
            about_profile.push('\n');
        }
    }
    // Created even when empty: pgo-check.sh takes a missing log for a build that didn't run this.
    // One write per rustc, appended, as cargo runs several at once.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?
        .write_all(about_profile.as_bytes())?;

    let code = output.status.code().unwrap_or(1);
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}
