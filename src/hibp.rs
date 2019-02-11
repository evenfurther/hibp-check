use failure::{format_err, Error};
use indicatif::ProgressBar;
use itertools::Itertools;
use log::debug;
use rayon::prelude::*;
use reqwest::Client;
use sha1::Sha1;
use std::collections::hash_map::HashMap;
use std::str;

fn pwned_suffixes(prefix: &str) -> Result<HashMap<String, usize>, Error> {
    let client = Client::new();
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    debug!("requesting {}", url);
    client
        .get(&url)
        .send()
        .map_err(Error::from)
        .and_then(|r| {
            if r.status().is_success() {
                Ok(r)
            } else {
                Err(format_err!(
                    "received error status code for {}: {}",
                    &url,
                    r.status()
                ))
            }
        })
        .and_then(|mut r| r.text().map_err(Error::from))
        .and_then(|lst| {
            lst.lines()
                .map(|l| {
                    let mut s = l.split(':');
                    let suffix = s.next().ok_or_else(|| format_err!("no entry found"))?;
                    let count = s
                        .next()
                        .ok_or_else(|| format_err!("no count found on line {}", l))?
                        .parse::<usize>()?;
                    Ok((suffix.to_owned(), count))
                })
                .collect()
        })
}

pub fn check_passwords(passwords: &[&str]) -> Result<Vec<usize>, Error> {
    let pb = ProgressBar::new(passwords.len() as u64);
    let mut sha1 = Sha1::new();
    let hashed = passwords
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            sha1.reset();
            sha1.update(p.as_bytes());
            (sha1.hexdigest().to_uppercase(), i)
        })
        .sorted()
        .group_by(|(sha, _)| sha.chars().take(5).collect::<String>())
        .into_iter()
        .map(|(g, e)| (g, e.collect_vec()))
        .collect_vec();
    let result = hashed
        .into_par_iter()
        .map(|(prefix, entries)| {
            pwned_suffixes(&prefix).map(|pwned| {
                entries
                    .into_iter()
                    .map(|(e, i)| {
                        pb.inc(1);
                        (i, pwned.get(&e[5..]).cloned().unwrap_or(0))
                    })
                    .collect_vec()
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .sorted()
        .map(|(_, n)| n)
        .collect_vec();
    pb.finish_and_clear();
    Ok(result)
}
