//! The custom authentication triggers, driven as Cognito drives them.

use cardea_core::Provider;

use super::*;
use crate::{
    native::{TicketKey, TicketKeyError, TicketKeySource},
    testing::native::{ANDROID, WEB, ticket_key},
};

fn define_event(session: Value) -> Value {
    json!({"triggerSource":"DefineAuthChallenge_Authentication","userPoolId":"pool",
        "userName":"u","callerContext":{"clientId":WEB},
        "request":{"userAttributes":{},"session":session},"response":{}})
}

fn step(name: &str, result: bool, metadata: &str) -> Value {
    json!({"challengeName":name,"challengeResult":result,"challengeMetadata":metadata})
}

fn ticket_step(result: bool) -> Value {
    step("CUSTOM_CHALLENGE", result, "CARDEA_PROVIDER_TICKET")
}

async fn answer(fixture: &Fixture, event: Value) -> Result<Value, TriggerError> {
    handle_challenge(&fixture.directory, &ticket_key("a1"), event)
        .await
        .map(|mut event| event["response"].take())
}

#[tokio::test]
async fn define_asks_once_and_issues_tokens_for_that_answer_alone() {
    let fixture = fixture().await;
    let ask = json!({"challengeName":"CUSTOM_CHALLENGE",
        "issueTokens":false,"failAuthentication":false});
    let pass = json!({"issueTokens":true,"failAuthentication":false});
    let fail = json!({"issueTokens":false,"failAuthentication":true});
    let cases = [
        (json!([]), &ask),
        (json!([ticket_step(true)]), &pass),
        // One wrong answer ends the session.
        (json!([ticket_step(false)]), &fail),
        (json!([ticket_step(false), ticket_step(true)]), &fail),
        (json!([ticket_step(true), ticket_step(true)]), &fail),
        // No SRP, password or MFA step belongs to this flow.
        (json!([step("SRP_A", true, "")]), &fail),
        (json!([step("PASSWORD_VERIFIER", true, "")]), &fail),
        (
            json!([step("SRP_A", true, ""), step("PASSWORD_VERIFIER", true, "")]),
            &fail,
        ),
        (json!([step("SMS_MFA", true, "")]), &fail),
        (
            json!([ticket_step(true), step("SOFTWARE_TOKEN_MFA", true, "")]),
            &fail,
        ),
        // A custom challenge somebody else defined.
        (json!([step("CUSTOM_CHALLENGE", true, "OTHER")]), &fail),
        (
            json!([{"challengeName":"CUSTOM_CHALLENGE","challengeResult":true}]),
            &fail,
        ),
        (
            json!([{"challengeName":"CUSTOM_CHALLENGE","challengeResult":"true",
                "challengeMetadata":"CARDEA_PROVIDER_TICKET"}]),
            &fail,
        ),
    ];
    for (session, expected) in cases {
        let response = answer(&fixture, define_event(session.clone()))
            .await
            .unwrap();
        assert_eq!(&response, expected, "{session}");
    }
    let mut no_session = define_event(json!([]));
    no_session["request"] = json!({});
    assert!(answer(&fixture, no_session).await.is_err());
}

#[tokio::test]
async fn an_unknown_user_looks_like_any_other_until_refused() {
    let fixture = fixture().await;
    let mut first = define_event(json!([]));
    first["request"]["userNotFound"] = json!(true);
    assert_eq!(
        answer(&fixture, first).await.unwrap()["challengeName"],
        "CUSTOM_CHALLENGE"
    );
    for result in [true, false] {
        let mut event = define_event(json!([ticket_step(result)]));
        event["request"]["userNotFound"] = json!(true);
        assert_eq!(
            answer(&fixture, event).await.unwrap(),
            json!({"issueTokens":false,"failAuthentication":true})
        );
    }
}

#[tokio::test]
async fn create_makes_only_the_first_custom_challenge() {
    let fixture = fixture().await;
    let event = |name: &str, session: Value| {
        json!({"triggerSource":"CreateAuthChallenge_Authentication","userPoolId":"pool",
            "request":{"challengeName":name,"session":session},"response":{}})
    };
    assert_eq!(
        answer(&fixture, event("CUSTOM_CHALLENGE", json!([])))
            .await
            .unwrap(),
        json!({"publicChallengeParameters":{"challenge":"PROVIDER_TICKET"},
            "privateChallengeParameters":{"challenge":"PROVIDER_TICKET"},
            "challengeMetadata":"CARDEA_PROVIDER_TICKET"})
    );
    for refused in [
        event("SRP_A", json!([])),
        event("PASSWORD_VERIFIER", json!([])),
        event("CUSTOM_CHALLENGE", json!([ticket_step(false)])),
    ] {
        assert!(matches!(
            answer(&fixture, refused).await,
            Err(TriggerError::UnexpectedChallenge)
        ));
    }
}

/// The verify event for `username` on `client`, as the pool describes the user.
fn verify_event(username: &str, sub: &str, client: &str, ticket: &str) -> Value {
    json!({"triggerSource":"VerifyAuthChallengeResponse_Authentication","userPoolId":"pool",
        "userName":username,"callerContext":{"clientId":client},
        "request":{"userAttributes":{"sub":sub},
            "privateChallengeParameters":{"challenge":"PROVIDER_TICKET"},
            "challengeAnswer":ticket},
        "response":{}})
}

async fn correct(fixture: &Fixture, event: Value) -> bool {
    answer(fixture, event).await.unwrap()["answerCorrect"] == true
}

/// Begin, define, create, verify, define, then the token trigger.
#[tokio::test]
async fn a_ticket_carries_a_sign_in_through_every_trigger() {
    let fixture = fixture().await;
    let product = product(&fixture);
    let issued = fixture
        .google_ticket("g-1", "owner@gmail.com")
        .await
        .unwrap();
    let asked = answer(&fixture, define_event(json!([]))).await.unwrap();
    assert_eq!(asked["challengeName"], "CUSTOM_CHALLENGE");
    let verify = verify_event(&issued.username, SUB, WEB, &issued.ticket);
    assert!(correct(&fixture, verify.clone()).await);
    let done = answer(&fixture, define_event(json!([ticket_step(true)])))
        .await
        .unwrap();
    assert_eq!(done["issueTokens"], true);
    let tokens = account_event("TokenGeneration_Authentication", SUB, "owner@gmail.com");
    handle(&fixture.directory, &product, tokens).await.unwrap();
    assert_eq!(product.accounts.lock().unwrap().len(), 1);
    // Replayed.
    assert!(!correct(&fixture, verify).await);
}

#[tokio::test]
async fn verify_refuses_whoever_and_wherever_the_ticket_is_not_for() {
    let fixture = fixture().await;
    let issued = fixture
        .google_ticket("g-1", "owner@gmail.com")
        .await
        .unwrap();
    let (name, ticket) = (issued.username.as_str(), issued.ticket.as_str());
    let right = verify_event(name, SUB, WEB, ticket);
    let mut unknown = right.clone();
    unknown["request"]["userNotFound"] = json!(true);
    unknown["request"]["userAttributes"] = json!({});
    let mut foreign = right.clone();
    foreign["request"]["privateChallengeParameters"] = json!({"challenge":"OTHER"});
    let mut silent = right.clone();
    silent["request"]["challengeAnswer"] = Value::Null;
    for event in [
        verify_event("another", SUB, WEB, ticket),
        verify_event(name, "another-sub", WEB, ticket),
        verify_event(name, SUB, ANDROID, ticket),
        verify_event(name, SUB, WEB, &"0".repeat(64)),
        unknown,
        foreign,
        silent,
    ] {
        assert!(!correct(&fixture, event.clone()).await, "{event}");
    }
    // The other spelling of the source Cognito documents.
    let mut spelled = right;
    spelled["triggerSource"] = json!("VerifyAuthChallenge_Authentication");
    assert!(correct(&fixture, spelled).await);
}

#[tokio::test]
async fn verify_needs_the_events_fields_and_a_key() {
    let fixture = fixture().await;
    for pointer in ["/userName", "/callerContext/clientId"] {
        let mut event = verify_event("u", SUB, WEB, &"0".repeat(64));
        *event.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(matches!(
            answer(&fixture, event).await,
            Err(TriggerError::MissingField(_))
        ));
    }
    struct NoKey;
    #[async_trait::async_trait]
    impl TicketKeySource for NoKey {
        async fn load(&self) -> Result<TicketKey, TicketKeyError> {
            Err(TicketKeyError::NoValue)
        }
    }
    let event = verify_event("u", SUB, WEB, &"0".repeat(64));
    let failed = handle_challenge(&fixture.directory, &NoKey, event).await;
    assert!(matches!(
        failed,
        Err(TriggerError::Identity(Error::Unavailable))
    ));
}

#[tokio::test]
async fn each_handler_serves_only_its_own_triggers() {
    let fixture = fixture().await;
    let product = product(&fixture);
    let challenge = define_event(json!([]));
    assert!(matches!(
        handle(&fixture.directory, &product, challenge).await,
        Err(TriggerError::Unsupported)
    ));
    let other = account_event("TokenGeneration_Authentication", SUB, "a@gmail.com");
    assert!(matches!(
        answer(&fixture, other).await,
        Err(TriggerError::Unsupported)
    ));
}

/// The redirect sign-in first: the native one reaches the same account.
#[tokio::test]
async fn a_redirect_sign_in_and_then_a_native_one_reach_one_account() {
    let fixture = fixture().await;
    let product = product(&fixture);
    handle(&fixture.directory, &product, google("owner@gmail.com"))
        .await
        .unwrap();
    let issued = fixture
        .google_ticket("g-1", "owner@gmail.com")
        .await
        .unwrap();
    assert_eq!(issued.username, "owner@gmail.com");
    assert!(
        correct(
            &fixture,
            verify_event(&issued.username, SUB, WEB, &issued.ticket)
        )
        .await
    );
    let pool = fixture.pool.state();
    assert_eq!((pool.creates, pool.links), (1, 1));
}

/// The native sign-in first: the redirect reaches the same account, with no
/// second one and no failed attempt.
#[tokio::test]
async fn a_native_sign_in_and_then_a_redirect_one_reach_one_account() {
    let fixture = fixture().await;
    let product = product(&fixture);
    fixture
        .google_ticket("g-1", "owner@gmail.com")
        .await
        .unwrap();
    let redirect = handle(&fixture.directory, &product, google("owner@gmail.com"))
        .await
        .unwrap();
    assert_eq!(
        redirect["response"]["userAttributesToMap"]["email"],
        "owner@gmail.com"
    );
    let signup = external_sign_up("google_g-1");
    handle(&fixture.directory, &product, signup).await.unwrap();
    let user = fixture
        .directory
        .provider(Provider::Google, "g-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.user_id, SUB);
    let pool = fixture.pool.state();
    assert_eq!((pool.creates, pool.links), (1, 1));
}
