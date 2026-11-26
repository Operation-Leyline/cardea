# identity

Shared Cognito sign-in and account linking for Leyline, Yoru and Pigeon:
one person is one account, whether they sign in with a password, Google or
Apple.

- `crates/identity-core`: rules (person key, providers, resolution). No AWS.
- `crates/identity-cognito`: directory table, Cognito triggers, linking.
- `packages/web`: browser sign-in, sessions and link-a-method hooks.
- `packages/cdk`: the user pool, providers, clients and table as one construct.

Read [DESIGN.md](DESIGN.md) first.
