#[macro_use]
extern crate clap;
extern crate csv;
extern crate itertools;
extern crate reqwest;
extern crate sha1;

use itertools::Itertools;
use std::collections::hash_set::HashSet;
use std::collections::hash_map::HashMap;
use std::str;

fn main() {
    run().unwrap();
}

fn run() -> Result<(), reqwest::Error> {
    let p = ["passw0rd", "sdklfjlsdkj", "123456"];
    let pawned = check_passwords(&p)?;
    for p in pawned {
        println!("Pawned: {}", p);
    }
    Ok(())
}

fn check_passwords<'a>(passwords: &'a [&'a str]) -> Result<Vec<&'a str>, reqwest::Error> {
    let mut sha1 = sha1::Sha1::new();
    let hashed: HashMap<String, &'a str> = passwords
        .iter()
        .map(|&p| {
            sha1.reset();
            sha1.update(p.as_bytes());
            (sha1.hexdigest().to_uppercase(), p)
        })
        .collect::<HashMap<_, _>>();
    let sorted: Vec<&[u8]> = hashed.keys().map(|s| s.as_bytes()).sorted();
    sorted
        .into_iter()
        .group_by(|&e| &e[..5])
        .into_iter()
        .flat_map(|(prefix, entries)| {
            match reqwest::get(&format!(
                "https://api.pwnedpasswords.com/range/{}",
                str::from_utf8(prefix).unwrap()
            )).and_then(|mut r| r.text())
            {
                Ok(lst) => {
                    let pawned = lst.lines().map(|s| &s.as_bytes()[..35]).collect::<HashSet<_>>();
                    entries
                        .filter(|e| pawned.contains(&e[5..]))
                        .map(|e| Ok(*hashed.get(str::from_utf8(e).unwrap()).unwrap()))
                        .collect_vec()
                }
                Err(e) => vec![Err(e)],
            }
        })
        .collect::<Result<Vec<_>, _>>()
}
