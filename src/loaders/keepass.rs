use super::Entry;
use anyhow::Error;
use clap::Parser;
use kdbx4::{CompositeKey, Kdbx4};
use std::path::{Path, PathBuf};

/// keepass
#[derive(Parser)]
pub struct Args {
    /// Get the password from the terminal
    #[clap(short, long)]
    ask_password: bool,
    /// The optional key file
    #[clap(short, long)]
    key_file: Option<PathBuf>,
    /// The optional password (unsafe on the command line)
    #[clap(short, long)]
    password: Option<String>,
    /// The file containing the passwords to check
    file: PathBuf,
}

pub fn load_entries<P1: AsRef<Path>, P2: AsRef<Path>>(
    file: P1,
    key: Option<&str>,
    keyfile: Option<P2>,
) -> Result<Vec<Entry>, Error> {
    let key = CompositeKey::new(key, keyfile)?;
    let db = Kdbx4::open(file, key)?;
    db.entries()
        .iter()
        .map(|entry| {
            Ok(Entry {
                designator: format!("{}/{}", entry.group(), entry.title()),
                password: entry.password()?,
            })
        })
        .collect()
}

pub fn load_from_subcommand(args: &Args) -> Result<Vec<Entry>, Error> {
    let password = if args.ask_password {
        rpassword::prompt_password("Enter keepass file password: ")?
    } else {
        args.password.clone().unwrap_or_default()
    };
    load_entries(
        &args.file,
        if password.is_empty() {
            None
        } else {
            Some(&password)
        },
        args.key_file.as_ref(),
    )
}
