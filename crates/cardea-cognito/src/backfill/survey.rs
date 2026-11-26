//! One read-only pass: what each pool user should have in the directory, what is
//! there, and what stands in the way.

use std::collections::HashMap;

use cardea_core::{
    EmailOwner, Error, NATIVE_ORIGIN, UNCONFIRMED_CLAIM_LIFETIME_SECONDS, User, normalize_email,
    person_key,
};

use super::{
    BackfillError, BackfillReport, Finding, Outcome, Problem, RowCounts, RowKind,
    pool::{PoolAccount, Standing},
};
use crate::{
    directory::{AwsDirectory, now, provider_key},
    methods::row::Identity,
    record::{EmailRow, MethodsRow, MethodsRowKey, ProviderRow},
};

/// A row the directory lacks.
pub(super) enum Missing {
    Claim(EmailRow),
    Binding(ProviderRow),
    List(MethodsRow),
}

impl Missing {
    pub(super) fn kind(&self) -> RowKind {
        match self {
            Self::Claim(_) => RowKind::Email,
            Self::Binding(_) => RowKind::Provider,
            Self::List(_) => RowKind::Methods,
        }
    }
}

/// What a pass found.
#[derive(Default)]
pub(super) struct Survey {
    users: usize,
    /// Rows already in place.
    pub present: RowCounts,
    /// Rows to write: a user's mailbox, then their list, then the bindings it
    /// leads to.
    pub missing: Vec<Missing>,
    findings: Vec<Finding>,
}

impl Survey {
    pub(super) fn into_report(self, outcome: Outcome) -> BackfillReport {
        let mut missing = RowCounts::default();
        for row in &self.missing {
            missing.add(row.kind());
        }
        BackfillReport {
            outcome,
            users: self.users,
            present: self.present,
            written: RowCounts::default(),
            missing,
            findings: self.findings,
        }
    }

    fn find(&mut self, user_id: &str, problem: Problem) {
        self.findings.push(Finding {
            user: user_id.to_owned(),
            problem,
        });
    }
}

/// Who else in the pool claims the same things.
#[derive(Default)]
struct Claimants<'a> {
    /// The ids at each person key.
    mailboxes: HashMap<String, Vec<&'a str>>,
    /// How many users link each `(provider, subject)`.
    subjects: HashMap<(&'static str, &'a str), usize>,
    /// The id behind each username.
    usernames: HashMap<&'a str, &'a str>,
}

impl<'a> Claimants<'a> {
    fn of(accounts: &'a [PoolAccount]) -> Self {
        let mut claimants = Self::default();
        for account in accounts {
            let Some(user_id) = account.user_id.as_deref() else {
                continue;
            };
            claimants.usernames.insert(&account.username, user_id);
            if let Some(Ok(person)) = account.email.as_deref().map(person_key) {
                claimants.mailboxes.entry(person).or_default().push(user_id);
            }
            for identity in account.identities.iter().flatten() {
                *claimants.subjects.entry(subject_of(identity)).or_default() += 1;
            }
        }
        claimants
    }
}

fn subject_of(identity: &Identity) -> (&'static str, &str) {
    (identity.provider.rule().cognito_name, &identity.subject)
}

/// Whether an existing mailbox row is `account`'s, or why it is not.
fn check_claim(
    row: &EmailRow,
    account: &PoolAccount,
    user: &User,
    claimants: &Claimants<'_>,
) -> Result<(), Problem> {
    if let Some(holder) = row.user_id.as_ref().filter(|id| **id != user.user_id) {
        return Err(Problem::MailboxHeld {
            holder: Some(holder.clone()),
        });
    }
    let bound = row.user_id.is_some();
    // A sign-in looks the row's username up, so it must still reach this
    // account: the pool's username, or the address, as signup writes it.
    let claimed = &row.record.username;
    if *claimed != user.username && !claimed.eq_ignore_ascii_case(&user.email) {
        return Err(if bound {
            Problem::StaleClaim
        } else {
            Problem::MailboxHeld {
                holder: claimants
                    .usernames
                    .get(claimed.as_str())
                    .map(|id| (*id).to_owned()),
            }
        });
    }
    if !bound && row.unconfirmed_expires_at.is_some() && account.standing != Standing::Unconfirmed {
        return Err(Problem::LapsingClaim);
    }
    Ok(())
}

/// The mailbox row `account` should have.
fn new_claim(account: &PoolAccount, user: &User, person: String) -> Result<EmailRow, Error> {
    let unconfirmed = account.standing == Standing::Unconfirmed;
    let origin = match (account.standing, account.first_provider()) {
        (Standing::Federated, Some(provider)) => provider.to_owned(),
        _ => NATIVE_ORIGIN.to_owned(),
    };
    Ok(EmailRow {
        person,
        record: EmailOwner {
            email: normalize_email(&user.email)?,
            username: user.username.clone(),
            origin,
        },
        user_id: (!unconfirmed).then(|| user.user_id.clone()),
        unconfirmed_expires_at: unconfirmed.then(|| now() + UNCONFIRMED_CLAIM_LIFETIME_SECONDS),
        password_initialization: None,
        password_set: match account.standing {
            Standing::Confirmed => Some(true),
            // Left to the origin's rule: confirming the signup writes nothing,
            // and the person did choose a password.
            Standing::Unconfirmed => None,
            Standing::Federated | Standing::NoPassword => Some(false),
        },
    })
}

impl AwsDirectory {
    /// List the pool and read every row its users should have.
    pub(super) async fn survey(&self) -> Result<Survey, BackfillError> {
        let accounts = self.all_accounts().await?;
        let claimants = Claimants::of(&accounts);
        let mut survey = Survey {
            users: accounts.len(),
            ..Survey::default()
        };
        for (position, account) in accounts.iter().enumerate() {
            self.survey_account(position, account, &claimants, &mut survey)
                .await?;
        }
        Ok(survey)
    }

    async fn survey_account(
        &self,
        position: usize,
        account: &PoolAccount,
        claimants: &Claimants<'_>,
        survey: &mut Survey,
    ) -> Result<(), BackfillError> {
        let Some(user_id) = account.user_id.clone() else {
            // Nothing opaque names this user but their place in the listing.
            survey.find(&format!("listed #{}", position + 1), Problem::NoUserId);
            return Ok(());
        };
        let Some((email, person)) = account
            .email
            .as_ref()
            .and_then(|email| Some((email.clone(), person_key(email).ok()?)))
        else {
            survey.find(&user_id, Problem::NoUsableEmail);
            return Ok(());
        };
        let identities = account.identities.as_deref().filter(|identities| {
            identities
                .iter()
                .all(|identity| !identity.subject.is_empty())
        });
        let federated = account.standing == Standing::Federated;
        let Some(identities) =
            identities.filter(|_| !federated || account.first_provider().is_some())
        else {
            survey.find(&user_id, Problem::UnreadableIdentities);
            return Ok(());
        };
        if federated {
            survey.find(&user_id, Problem::FederatedOnly);
        } else if account.standing != Standing::Unconfirmed && !account.email_verified {
            survey.find(&user_id, Problem::UnverifiedEmail);
        }
        if account.has_unsupported_provider() {
            survey.find(&user_id, Problem::UnsupportedProvider);
        }
        let sharing = &claimants.mailboxes[&person];
        if sharing.len() > 1 {
            let with = sharing
                .iter()
                .filter(|other| **other != user_id)
                .map(|other| (*other).to_owned())
                .collect();
            survey.find(&user_id, Problem::SharedMailbox { with });
            return Ok(());
        }
        let user = User {
            user_id,
            username: account.username.clone(),
            email,
        };
        // A user whose mailbox is in question gets no other row either.
        match self.email_row(&user.email).await {
            Ok(Some(row)) => match check_claim(&row, account, &user, claimants) {
                Ok(()) => survey.present.add(RowKind::Email),
                Err(problem) => {
                    survey.find(&user.user_id, problem);
                    return Ok(());
                }
            },
            Ok(None) => survey
                .missing
                .push(Missing::Claim(new_claim(account, &user, person)?)),
            Err(Error::Conflict) => {
                let row = RowKind::Email;
                survey.find(&user.user_id, Problem::UnreadableRow { row });
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        // The list first, so that a run that stops leaves no binding without it.
        if !identities.is_empty() {
            self.survey_list(&user, identities, survey).await?;
        }
        for identity in identities {
            self.survey_binding(&user, identity, claimants, survey)
                .await?;
        }
        Ok(())
    }

    async fn survey_binding(
        &self,
        user: &User,
        identity: &Identity,
        claimants: &Claimants<'_>,
        survey: &mut Survey,
    ) -> Result<(), BackfillError> {
        let provider = identity.provider;
        if claimants.subjects[&subject_of(identity)] > 1 {
            survey.find(&user.user_id, Problem::SharedSubject { provider });
            return Ok(());
        }
        let key = provider_key(provider, &identity.subject)?;
        match self.row::<ProviderRow>(key).await {
            Ok(Some(row)) if row.record == *user => survey.present.add(RowKind::Provider),
            Ok(Some(row)) if row.record.user_id == user.user_id => {
                survey.find(&user.user_id, Problem::StaleBinding { provider });
            }
            Ok(Some(row)) => {
                let holder = row.record.user_id;
                survey.find(&user.user_id, Problem::SubjectBound { provider, holder });
            }
            Ok(None) => survey.missing.push(Missing::Binding(ProviderRow {
                provider: ProviderRow::provider_name(provider),
                subject: identity.subject.clone(),
                record: user.clone(),
            })),
            Err(Error::Conflict) => {
                let row = RowKind::Provider;
                survey.find(&user.user_id, Problem::UnreadableRow { row });
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// A list already there is left as it is: listing, linking and unlinking
    /// keep it up to date.
    async fn survey_list(
        &self,
        user: &User,
        identities: &[Identity],
        survey: &mut Survey,
    ) -> Result<(), BackfillError> {
        let key = MethodsRowKey::new(user.user_id.clone()).map_err(|_| Error::Invalid)?;
        match self.row::<MethodsRow>(key).await {
            Ok(Some(_)) => survey.present.add(RowKind::Methods),
            Ok(None) => {
                let mut list = MethodsRow::empty(user);
                list.version = 1;
                for identity in identities {
                    list.entry(identity);
                }
                survey.missing.push(Missing::List(list));
            }
            Err(Error::Conflict) => {
                let row = RowKind::Methods;
                survey.find(&user.user_id, Problem::UnreadableRow { row });
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}
