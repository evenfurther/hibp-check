//! This module is the only one which should be allowed to perform network requests
//! in order to ease auditing. It contains a single function.

use anyhow::{ensure, Error};
use lazy_static::lazy_static;
use reqwest::Client;

static HIBP_BASE: &str = "https://api.pwnedpasswords.com/range";

lazy_static! {
    static ref CLIENT: Client = Client::new();
}

/// Request page from HIBP check containing suffixes and pwned count for
/// a given prefix.
pub async fn hibp_network_request(prefix: &str) -> Result<String, Error> {
    let url = format!("{}/{}", HIBP_BASE, prefix);
    let response = CLIENT.get(&url).send().await?;
    ensure!(
        response.status().is_success(),
        "received error status code for {}: {}",
        &url,
        response.status()
    );
    Ok(response.text().await?)
}
