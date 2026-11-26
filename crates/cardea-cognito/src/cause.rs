//! An error's text for a log line.

/// `error` with its cause chain, `a: b: c`. An SDK error displays as only
/// "service error"; the part that says which one is sources down.
pub(crate) fn cause(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        source = inner.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_is_named() {
        let inner = std::io::Error::other("refused");
        let outer = crate::triggers::ProductError::new(inner);
        assert_eq!(cause(&outer), "refused");
        assert_eq!(
            cause(&crate::mail::MailError::Delivery(outer)),
            "Cognito email delivery failed: refused"
        );
    }
}
