use crate::network;
use anyhow::{format_err, Error};
use futures::future::{self, FutureExt};
use indicatif::ProgressBar;
use itertools::Itertools;
use rayon::prelude::*;
use sha1::Sha1;
use std::collections::hash_map::HashMap;
use std::str;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Id(usize);

/// Given `entries` consisting in `(hash, id)` couples with all hashes starting with
/// the same prefix, associate each id with the number of times this has has been
/// pwned.
async fn check_prefix(entries: Vec<(String, Id)>) -> Result<Vec<(Id, usize)>, Error> {
    let prefix = &entries[0].0[..5];
    let pwned = pwned_suffixes(prefix).await?;
    Ok(entries
        .into_iter()
        .map(|(e, i)| (i, pwned.get(&e[5..]).copied().unwrap_or(0)))
        .collect_vec())
}

/// Split a `0..len` range into `parts` equal ranges (the last
/// one might be smaller).
fn split_range(len: usize, parts: usize) -> Vec<std::ops::Range<usize>> {
    let size = (len + parts - 1) / parts;
    (0..parts)
        .map(|part| part * size..((part + 1) * size).min(len))
        .collect()
}

/// Group passwords by hash prefix.
///
/// Given a list of passwords, return a list of `(prefix, items)` with `prefix`
/// being the prefix of the hashed password and every item being a couple
/// `(hash, index)` where `index` is the password index in the original list.
fn hashed_passwords(passwords: &[&str]) -> Vec<Vec<(String, Id)>> {
    split_range(passwords.len(), num_cpus::get())
        .into_par_iter()
        .flat_map(|range| {
            let mut sha1 = Sha1::new();
            let start = range.start;
            passwords[range]
                .iter()
                .enumerate()
                .map(|(i, p)| (Id(i + start), p))
                .map(|(i, &p)| {
                    sha1.reset();
                    sha1.update(p.as_bytes());
                    (sha1.hexdigest().to_uppercase(), i)
                })
                .collect_vec()
        })
        .collect::<Vec<_>>()
        .into_iter()
        .sorted()
        .group_by(|(sha, _)| sha.chars().take(5).collect::<String>())
        .into_iter()
        .map(|(_, e)| e.collect_vec())
        .collect_vec()
}

/// Check passwords against HIBP database and return a vector of number of
/// occurrences in the same order as the original passwords.
pub async fn check_passwords(
    passwords: &[&str],
    pb: Option<&ProgressBar>,
) -> Result<Vec<usize>, Error> {
    let occurrences = future::join_all(hashed_passwords(passwords).into_iter().map(|entries| {
        let len = entries.len();
        check_prefix(entries).map(move |result| {
            if let Some(pb) = pb {
                pb.inc(len as u64);
            }
            result
        })
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let result = occurrences
        .into_iter()
        .flatten()
        .sorted()
        .map(|(_, n)| n)
        .collect_vec();
    Ok(result)
}

/// For a given prefix, return a map of pwned suffixes along with a number of occurrences where
/// a password hashed into (prefix+suffix) was used.
pub async fn pwned_suffixes(prefix: &str) -> Result<HashMap<String, usize>, Error> {
    let lst = network::hibp_network_request(prefix).await?;
    lst.lines()
        .map(|l| {
            let (suffix, count) = l
                .split_once(':')
                .ok_or_else(|| format_err!("no count found on line"))?;
            let count = count.parse::<usize>()?;
            Ok((suffix.to_owned(), count))
        })
        .collect()
}
