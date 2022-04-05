use anyhow::Error;
use clap::{Parser, Subcommand};
use indicatif::ProgressBar;
use itertools::Itertools;
use std::{cmp::Reverse, collections::HashMap};
mod hibp;
mod loaders;
mod network;

#[derive(Parser)]
#[clap(version, author, about)]
struct Args {
    /// Show the pwned passwords in output
    #[clap(short, long, global = true)]
    show_passwords: bool,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keepass(loaders::keepass::Args),
}

#[tokio::main]
pub async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let mut entries = match args.command {
        Command::Keepass(args) => loaders::keepass::load_from_subcommand(&args)?,
    };
    loaders::remove_common_prefix(&mut entries);
    let passwords: Vec<&str> = entries.iter().map(|e| e.password.as_str()).collect();
    let pwned = hibp::check_passwords(&passwords, Some(&ProgressBar::new(passwords.len() as u64)))
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();
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
        if args.show_passwords {
            println!(" ({})", entry.password);
        } else {
            println!();
        }
    }
    Ok(())
}
