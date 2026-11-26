# Cardea

Named for Cardea, the Roman goddess of door hinges, whose power is "to open
what is shut, to shut what is open".

Shared Cognito sign-in and account linking for Leyline, Yoru and Pigeon:
one person is one account, whether they sign in with a password, Google or
Apple.

- `crates/cardea-core`: rules (person key, providers, resolution). No AWS.
- `crates/cardea-cognito`: directory table, Cognito triggers, linking.
- `packages/web`: browser sign-in, sessions and link-a-method hooks.
- `packages/cdk`: the user pool, providers, clients and table as one construct.

Read [DESIGN.md](DESIGN.md) first.
