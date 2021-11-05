use anyhow::Error;
use clap::{load_yaml, App};
use indicatif::ProgressBar;
use itertools::Itertools;
use std::{cmp::Reverse, collections::HashMap};
mod hibp;
mod loaders;
mod network;

#[tokio::main]
pub async fn main() -> Result<(), Error> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let mut entries = Vec::new();
    if let Some(matches) = matches.subcommand_matches("keepass") {
        entries = loaders::keepass::load_from_subcommand(matches)?;
    }
    loaders::remove_common_prefix(&mut entries);
    let passwords: Vec<&str> = entries.iter().map(|e| e.password.as_str()).collect();
    let pwned = hibp::check_passwords(&passwords, Some(&ProgressBar::new(passwords.len() as u64)))
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();
    let show_passwords = matches.occurrences_of("password") > 0;
    for (entry, occurrences) in entries
        .iter()
        .map(|e| (e, pwned[e.password.as_str()]))
        .filter(|&(_, n)| n > 0)
        .sorted_unstable_by_key(|&(_, n)| Reverse(n))
    {
        print!(
            "Password for {} found {} time{}",
            entry.designator,
            occurrences,
            if occurrences > 1 { "s" } else { "" }
        );
        if show_passwords {
            println!(" ({})", entry.password);
        } else {
            println!();
        }
    }
    Ok(())
}
