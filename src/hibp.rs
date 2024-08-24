use crate::network;
use anyhow::{format_err, Error};
use futures::future::{self, FutureExt};
use indicatif::ProgressBar;
use itertools::Itertools;
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use std::collections::hash_map::HashMap;
use std::str;

/// Given `entries` consisting in `(hash, password)` couples with all hashes starting with
/// the same prefix, associate each password with the number of times this has has been
/// pwned.
async fn check_prefix(entries: Vec<(String, &str)>) -> Result<Vec<(&str, usize)>, Error> {
    let prefix = &entries[0].0[..5];
    let pwned = pwned_suffixes(prefix).await?;
    Ok(entries
        .into_iter()
        .map(|(e, p)| (p, pwned.get(&e[5..]).copied().unwrap_or(0)))
        .collect_vec())
}

/// Group passwords by hash prefix.
///
/// Given a list of passwords, return a list of list of `(hash, password)`
/// grouped by prefix.
fn hashed_passwords<'a>(passwords: &[&'a str]) -> Vec<Vec<(String, &'a str)>> {
    passwords
        .into_par_iter()
        .map(|p| {
            let mut sha1 = Sha1::default();
            sha1.update(p.as_bytes());
            (format!("{:X}", sha1.finalize()), *p)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .sorted()
        .chunk_by(|(sha, _)| sha.chars().take(5).collect::<String>())
        .into_iter()
        .map(|(_, e)| e.collect_vec())
        .collect_vec()
}

/// Check passwords against HIBP database and return the number of occurrences.
pub async fn check_passwords<'a>(
    passwords: &[&'a str],
    pb: Option<&ProgressBar>,
) -> Result<Vec<(&'a str, usize)>, Error> {
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
    .collect::<Result<Vec<Vec<(&str, usize)>>, _>>()?;
    let result = occurrences.into_iter().flatten().collect_vec();
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

#[test]
fn test_hashed_passwords() {
    let passwords = vec!["BWE!y4xj:i", "NvLK25b+", "xQS?"];
    let hashed = hashed_passwords(&passwords);
    let expected = vec![
        vec![
            (
                String::from("8E7334AB061EAB6673D2C591D6C77CEEE12DE961"),
                "xQS?",
            ),
            (
                String::from("8E7336BBDBE0B7F31DE9A06B053ECDF5E356A946"),
                "BWE!y4xj:i",
            ),
        ],
        vec![(
            String::from("EF867658E9572AC965BBDC5212FAE656570DB09B"),
            "NvLK25b+",
        )],
    ];
    assert_eq!(expected, hashed);
}
