//! What a backfill did, in counts and opaque user ids.

use std::fmt;

use cardea_core::Provider;

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing was written.
    DryRun,
    /// The missing rows were written; the directory stays closed.
    Applied,
    /// The rows were written and the directory opened.
    Activated,
    /// The directory stays closed: the second pass did not find every user
    /// covered.
    ActivationRefused,
    /// The directory was open before this run, which therefore wrote nothing.
    AlreadyActive,
}

/// A kind of directory row the backfill writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    /// `EMAIL#`.
    Email,
    /// `PROVIDER#`.
    Provider,
    /// `METHODS#`.
    Methods,
}

/// A number of rows of each kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowCounts {
    /// Mailbox rows.
    pub emails: usize,
    /// Provider bindings.
    pub providers: usize,
    /// Identity lists.
    pub methods: usize,
}

impl RowCounts {
    pub(super) fn add(&mut self, kind: RowKind) {
        match kind {
            RowKind::Email => self.emails += 1,
            RowKind::Provider => self.providers += 1,
            RowKind::Methods => self.methods += 1,
        }
    }
}

/// Something an operator should know about one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The user's `sub`; their place in the listing if they have none.
    pub user: String,
    /// What it is.
    pub problem: Problem,
}

/// What a [`Finding`] says. [`Problem::blocks`] tells those that keep the
/// directory closed from notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The pool gives the user no `sub`.
    NoUserId,
    /// No address, or one that cannot be read. Nothing was written.
    NoUsableEmail,
    /// The list of linked identities cannot be read. Nothing was written.
    UnreadableIdentities,
    /// Other pool users have the same mailbox. Nothing was written for any.
    SharedMailbox {
        /// The others.
        with: Vec<String>,
    },
    /// The mailbox's row is another's. Nothing was written for this user.
    MailboxHeld {
        /// The user the row names, when it can be told.
        holder: Option<String>,
    },
    /// The mailbox's row names this user under a username that is neither the
    /// pool's nor their address, which a sign-in cannot follow. Nothing was
    /// written for them.
    StaleClaim,
    /// The mailbox's row is this user's unconfirmed claim, which will lapse,
    /// although the user is past confirmation.
    LapsingClaim,
    /// More than one pool user links one identity of this provider.
    SharedSubject {
        /// Whose identity.
        provider: Provider,
    },
    /// An identity the pool links onto this user is bound to another.
    SubjectBound {
        /// Whose identity.
        provider: Provider,
        /// The user the binding names.
        holder: String,
    },
    /// A binding names this user with a username or address the pool no longer
    /// holds, which a sign-in refuses.
    StaleBinding {
        /// Whose identity.
        provider: Provider,
    },
    /// A row of this user's does not decode.
    UnreadableRow {
        /// Which row.
        row: RowKind,
    },
    /// A note: the user exists only behind a provider sign-in. The rows point
    /// at them, but Cardea signs people in to native users.
    FederatedOnly,
    /// A note: the account's address is not verified, and was claimed.
    UnverifiedEmail,
    /// A note: an identity of a provider Cardea does not know, whose sign-ins
    /// its triggers refuse. It got no binding.
    UnsupportedProvider,
}

impl Problem {
    /// Whether the directory must stay closed until this is settled.
    pub fn blocks(&self) -> bool {
        !matches!(
            self,
            Self::FederatedOnly | Self::UnverifiedEmail | Self::UnsupportedProvider
        )
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = |provider: &Provider| provider.rule().display_name;
        match self {
            Self::NoUserId => f.write_str("has no sub"),
            Self::NoUsableEmail => f.write_str("has no usable email address"),
            Self::UnreadableIdentities => {
                f.write_str("has a list of identities that cannot be read")
            }
            Self::SharedMailbox { with } => {
                write!(f, "shares one mailbox with {}", with.join(", "))
            }
            Self::MailboxHeld { holder: Some(id) } => {
                write!(f, "has a mailbox whose row belongs to {id}")
            }
            Self::MailboxHeld { holder: None } => {
                f.write_str("has a mailbox whose row belongs to another claim")
            }
            Self::StaleClaim => {
                f.write_str("has a mailbox row under a username the pool no longer answers to")
            }
            Self::LapsingClaim => f.write_str(
                "is past confirmation but holds a claim that lapses; delete that row and run again",
            ),
            Self::SharedSubject { provider } => {
                write!(
                    f,
                    "links a {} identity another user links too",
                    name(provider)
                )
            }
            Self::SubjectBound { provider, holder } => write!(
                f,
                "links a {} identity that is bound to {holder}",
                name(provider)
            ),
            Self::StaleBinding { provider } => write!(
                f,
                "has a {} binding with an outdated username or address",
                name(provider)
            ),
            Self::UnreadableRow { row } => {
                let row = match row {
                    RowKind::Email => "mailbox row",
                    RowKind::Provider => "provider binding",
                    RowKind::Methods => "identity list",
                };
                write!(f, "has a {row} that cannot be read")
            }
            Self::FederatedOnly => f.write_str(
                "exists only behind a provider sign-in; Cardea expects a native account, \
                 so convert this user before they sign in again",
            ),
            Self::UnverifiedEmail => f.write_str("has an unverified email address"),
            Self::UnsupportedProvider => f.write_str("links a provider Cardea does not support"),
        }
    }
}

/// The result of [`backfill`](super::backfill). Its `Display` is what the
/// binary prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillReport {
    /// How the run ended.
    pub outcome: Outcome,
    /// Users the pool listed in the last pass, linked identities' own profiles
    /// apart.
    pub users: usize,
    /// Rows that were in place before the run.
    pub present: RowCounts,
    /// Rows this run wrote.
    pub written: RowCounts,
    /// Rows the last pass found absent: what an apply would write after a dry
    /// run.
    pub missing: RowCounts,
    /// What the last pass found, in the pool's listing order.
    pub findings: Vec<Finding>,
}

impl BackfillReport {
    /// Whether an operator has something to settle: a blocking finding, a row
    /// an apply left missing, or a refused activation.
    pub fn needs_attention(&self) -> bool {
        let left = self.outcome != Outcome::DryRun && self.missing != RowCounts::default();
        left || self.outcome == Outcome::ActivationRefused
            || self.findings.iter().any(|finding| finding.problem.blocks())
    }
}

impl fmt::Display for RowCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} email claims, {} provider bindings, {} identity lists",
            self.emails, self.providers, self.methods
        )
    }
}

impl fmt::Display for BackfillReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match self.outcome {
            Outcome::DryRun => "dry run, nothing written",
            Outcome::Applied => "applied, the directory is still closed",
            Outcome::Activated => "applied and activated",
            Outcome::ActivationRefused => {
                "activation refused: not every user is covered, the directory is still closed"
            }
            Outcome::AlreadyActive => "the directory is already active, nothing written",
        };
        writeln!(f, "outcome: {outcome}")?;
        writeln!(f, "pool users: {}", self.users)?;
        writeln!(f, "rows already in place: {}", self.present)?;
        writeln!(f, "rows written: {}", self.written)?;
        writeln!(f, "rows missing: {}", self.missing)?;
        for (title, blocking) in [("to settle", true), ("notes", false)] {
            let findings: Vec<&Finding> = self
                .findings
                .iter()
                .filter(|finding| finding.problem.blocks() == blocking)
                .collect();
            writeln!(f, "{title}: {}", findings.len())?;
            for finding in findings {
                writeln!(f, "  user {} {}", finding.user, finding.problem)?;
            }
        }
        Ok(())
    }
}
