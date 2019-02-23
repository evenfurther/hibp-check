pub mod keepass;

pub struct Entry {
    pub designator: String,
    pub password: String,
}

fn common_prefix(entries: &[Entry]) -> Option<String> {
    let first = &entries.get(0)?.designator;
    for (i, _) in first.rmatch_indices('/') {
        let prefix = &first[0..i + 1];
        if entries.iter().skip(1).all(|e| e.designator.starts_with(prefix)) {
            return Some(prefix.to_owned());
        }
    }
    None
}

pub fn remove_common_prefix(entries: &mut [Entry]) {
    if let Some(prefix) = common_prefix(entries) {
        let trim = prefix.len();
        for e in entries.iter_mut() {
            e.designator = e.designator.chars().skip(trim).collect();
        }
    }
}
