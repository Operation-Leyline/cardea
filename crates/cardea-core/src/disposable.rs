//! The disposable-domain blocklist: signup refuses a throwaway address before
//! anything is reserved.
//!
//! The list is a checked-in file compiled into the binary. Signup never makes
//! a network call to decide, so there is no outage to depend on;
//! `tools/refresh_disposable_domains.py` regenerates the file and a person
//! reviews the diff.
use std::{collections::HashSet, sync::OnceLock};

const LIST: &str = include_str!("disposable_domains.txt");

fn domains() -> &'static HashSet<&'static str> {
    static DOMAINS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        LIST.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// Whether the address's domain, or a parent of it, is on the list. A listed
/// `mailinator.com` also covers `team.mailinator.com`: a throwaway service
/// hands out subdomains as readily as addresses.
pub fn is_disposable(email: &str) -> bool {
    let Some((_, domain)) = email.trim().rsplit_once('@') else {
        return false;
    };
    let domain = domain.trim_end_matches('.').to_lowercase();
    let list = domains();
    let mut candidate = domain.as_str();
    loop {
        if list.contains(candidate) {
            return true;
        }
        match candidate.split_once('.') {
            Some((_, parent)) if parent.contains('.') => candidate = parent,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_domains_and_their_subdomains_are_disposable() {
        for email in [
            "a@mailinator.com",
            "A@Mailinator.COM",
            "a@team.mailinator.com",
            "a@deep.team.mailinator.com",
            " a@yopmail.com ",
            "a@guerrillamail.com.",
        ] {
            assert!(is_disposable(email), "{email}");
        }
    }

    #[test]
    fn ordinary_providers_and_lookalikes_are_not() {
        for email in [
            "a@gmail.com",
            "a@example.com",
            "a@mailinator.com.example.org",
            "a@mailinator.example",
            "no-at-sign",
            "",
        ] {
            assert!(!is_disposable(email), "{email}");
        }
    }

    /// The list is data a script rewrites: a malformed refresh must fail here,
    /// not silently stop blocking.
    #[test]
    fn the_list_is_sorted_lowercase_and_free_of_the_big_providers() {
        let entries: Vec<&str> = LIST
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert!(entries.len() > 500, "the list looks truncated");
        let mut sorted = entries.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(entries, sorted, "sorted, one entry per domain");
        for entry in &entries {
            assert_eq!(*entry, entry.to_lowercase());
            assert!(entry.contains('.') && !entry.contains(['@', ' ', '/']));
        }
        for provider in [
            "gmail.com",
            "googlemail.com",
            "outlook.com",
            "hotmail.com",
            "yahoo.com",
            "icloud.com",
            "proton.me",
            "protonmail.com",
            "aol.com",
        ] {
            assert!(
                !entries.contains(&provider),
                "{provider} must never be blocked"
            );
        }
    }
}
