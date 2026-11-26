//! Email addresses: the address mail is delivered to, and the person behind it.

use crate::Error;

/// The address as written, lowercased and checked: where mail is delivered.
/// It is never folded, so `First.Last+news@example.com` keeps the spelling
/// its owner gave. Uniqueness and quotas use [`person_key`] instead.
pub fn normalize_email(email: &str) -> Result<String, Error> {
    let email = email.trim().to_lowercase();
    let (local, domain) = email.rsplit_once('@').ok_or(Error::Invalid)?;
    if local.is_empty()
        || domain.is_empty()
        || email.len() > 320
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
        || local.contains('@')
    {
        return Err(Error::Invalid);
    }
    Ok(email)
}

/// The mailbox behind an address: every spelling that reaches one inbox maps
/// to one key. The identity directory is keyed by it, and a product's
/// per-person quota should be too, so it holds across every sign-in method.
///
/// The rule is lowercase, drop a `+tag` from the local part on every domain,
/// drop the local part's dots on Gmail (`googlemail.com` is Gmail), and read
/// `me.com` and `mac.com` as `icloud.com`: Apple delivers all three to one
/// mailbox. Without it `a.b+1@gmail.com`, `a.b+2@gmail.com` and `ab@gmail.com` are
/// three people, and a per-person allowance can be farmed with aliases. A
/// provider that treats a tag as a distinct mailbox only loses the chance to
/// sign up twice with one root address. The delivery address is untouched
/// (see [`normalize_email`]).
pub fn person_key(email: &str) -> Result<String, Error> {
    let email = normalize_email(email)?;
    let (local, domain) = email.rsplit_once('@').ok_or(Error::Invalid)?;
    let domain = match domain {
        "googlemail.com" => "gmail.com",
        "me.com" | "mac.com" => "icloud.com",
        other => other,
    };
    // An address that is all tag (`+x@host`) keeps its tag: there is no
    // mailbox name left to fold to.
    let untagged = local.split('+').next().filter(|s| !s.is_empty());
    let mut folded = untagged.unwrap_or(local).to_owned();
    if domain == "gmail.com" {
        let dotless = folded.replace('.', "");
        if !dotless.is_empty() {
            folded = dotless;
        }
    }
    Ok(format!("{folded}@{domain}"))
}

/// Whether two addresses reach one mailbox, by [`person_key`]. An address
/// that does not normalize reaches none.
pub fn same_mailbox(a: &str, b: &str) -> bool {
    matches!((person_key(a), person_key(b)), (Ok(a), Ok(b)) if a == b)
}

/// Whether the reader of `held` is known to receive `invited`'s mail: the same
/// address, or two spellings of one Gmail mailbox. [`person_key`] also folds a
/// `+tag` on other domains, where a provider may deliver it to someone else, so
/// that fold alone proves nothing about who reads the mail.
pub fn same_inbox(held: &str, invited: &str) -> bool {
    let (Ok(held), Ok(invited)) = (normalize_email(held), normalize_email(invited)) else {
        return false;
    };
    held == invited
        || (same_mailbox(&held, &invited)
            && person_key(&held).is_ok_and(|key| key.ends_with("@gmail.com")))
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
