//! Cognito's custom authentication flow, as [native sign-in](crate::native)
//! uses it: one challenge, answered with a ticket.
//!
//! The flow is `InitiateAuth` with `CUSTOM_AUTH` and a username, then
//! `RespondToAuthChallenge` with the ticket. Nothing else is part of it: a
//! session that holds an SRP step, a password, a second challenge or a wrong
//! answer ends without tokens.
//!
//! Anyone can start the flow for any username. For one the pool does not have
//! (`userNotFound`, on a client that hides user existence) every step looks and
//! costs the same as for one it has, up to the refusal.

use serde_json::{Value, json};

use super::TriggerError;
use crate::{
    directory::{AwsDirectory, now},
    native::{
        TicketKeySource,
        ticket::{Binding, redeem},
    },
};

/// Cognito's name for a challenge a trigger defines.
const CUSTOM_CHALLENGE: &str = "CUSTOM_CHALLENGE";
/// What the challenge asks for, told to the client and kept for the check.
const TICKET_CHALLENGE: &str = "PROVIDER_TICKET";
/// How the session records that the challenge was this library's.
const METADATA: &str = "CARDEA_PROVIDER_TICKET";

/// Whether `source` is one of the three custom authentication triggers. Cognito
/// documents two spellings of the verify trigger's source.
pub(super) fn serves(source: &str) -> bool {
    [
        "DefineAuthChallenge_",
        "CreateAuthChallenge_",
        "VerifyAuthChallenge",
    ]
    .iter()
    .any(|prefix| source.starts_with(prefix))
}

fn session(payload: &Value) -> Result<&[Value], TriggerError> {
    payload["request"]["session"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or(TriggerError::MissingField("session"))
}

/// `DefineAuthChallenge`: ask for the ticket once; issue tokens only for that
/// one challenge answered correctly; refuse everything else.
pub(super) fn define(mut payload: Value) -> Result<Value, TriggerError> {
    let unknown = payload["request"]["userNotFound"] == true;
    let response = match session(&payload)? {
        [] => json!({"challengeName": CUSTOM_CHALLENGE,
            "issueTokens": false, "failAuthentication": false}),
        [only]
            if !unknown
                && only["challengeName"] == CUSTOM_CHALLENGE
                && only["challengeMetadata"] == METADATA
                && only["challengeResult"] == true =>
        {
            json!({"issueTokens": true, "failAuthentication": false})
        }
        _ => json!({"issueTokens": false, "failAuthentication": true}),
    };
    payload["response"] = response;
    Ok(payload)
}

/// `CreateAuthChallenge`: the ticket challenge, and only as the first step.
/// There is nothing secret to hand out: the ticket is the client's already.
pub(super) fn create(mut payload: Value) -> Result<Value, TriggerError> {
    if payload["request"]["challengeName"] != CUSTOM_CHALLENGE || !session(&payload)?.is_empty() {
        return Err(TriggerError::UnexpectedChallenge);
    }
    payload["response"] = json!({
        "publicChallengeParameters": {"challenge": TICKET_CHALLENGE},
        "privateChallengeParameters": {"challenge": TICKET_CHALLENGE},
        "challengeMetadata": METADATA,
    });
    Ok(payload)
}

/// `VerifyAuthChallengeResponse`: redeem the ticket for the user and app client
/// the event names.
pub(super) async fn verify(
    directory: &AwsDirectory,
    keys: &(impl TicketKeySource + ?Sized),
    mut payload: Value,
) -> Result<Value, TriggerError> {
    let request = &payload["request"];
    let required = |value: &'_ Value, name| {
        value
            .as_str()
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .ok_or(TriggerError::MissingField(name))
    };
    let username = required(&payload["userName"], "user name")?;
    let client_id = required(&payload["callerContext"]["clientId"], "app client")?;
    // Absent for a user the pool does not have, whose ticket then names no row.
    let user_id = request["userAttributes"]["sub"]
        .as_str()
        .unwrap_or_default();
    let ticket = request["challengeAnswer"].as_str().unwrap_or_default();
    let binding = Binding {
        username: &username,
        user_id,
        client_id: &client_id,
    };
    let ours = request["privateChallengeParameters"]["challenge"] == TICKET_CHALLENGE;
    let unknown = request["userNotFound"] == true;
    let time = u64::try_from(now()).unwrap_or(0);
    let redeemed = ours && redeem(directory, keys, binding, ticket, time).await?;
    payload["response"] = json!({"answerCorrect": redeemed && !unknown});
    Ok(payload)
}
