use super::Entry;
use anyhow::Error;
use clap::{arg, ArgMatches, Command};
use kdbx4::{CompositeKey, Kdbx4};
use std::path::Path;

pub fn cli() -> Command<'static> {
    Command::new("keepass")
        .arg(arg!(-a --"ask-password" "Get the password from the terminal"))
        .arg(arg!(-k --"key-file" [FILE] "The optional key file"))
        .arg(arg!(-p --password "The optional password (unsafe on the command line)"))
        .arg(arg!(<FILE> "The file containing the passwords to check"))
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

pub fn load_from_subcommand(matches: &ArgMatches) -> Result<Vec<Entry>, Error> {
    let password = if matches.occurrences_of("ask-password") > 0 {
        rpassword::prompt_password("Enter keepass file password: ")?
    } else {
        matches.value_of("password").unwrap_or("").to_owned()
    };
    load_entries(
        matches.value_of("FILE").unwrap(),
        if password.is_empty() {
            None
        } else {
            Some(&password)
        },
        matches.value_of("key-file"),
    )
}
