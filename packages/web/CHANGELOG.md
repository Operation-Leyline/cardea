# Changelog

## Unreleased

### Breaking: `providerSession` replaces the single-app Google importer

The legacy-session importer that had one app's storage key built in is gone,
along with its export. `providerSession` takes the key as configuration; the
module is now `legacy/provider-session.ts`.

To keep reading the same sessions, replace the old no-argument importer with:

```ts
providerSession({ key: "<app>.google.session.{clientId}.{issuer}" })
```

where `<app>` is the first segment of the key your app saved. The record's
property names and the provider (Google) are the defaults, so nothing else needs
setting. `fields` and `provider` cover other records; see the README, "Keeping
people signed in on adoption".

`cognitoSdkSession` is unchanged.
