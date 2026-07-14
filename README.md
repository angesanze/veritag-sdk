# veritag-sdk

The Veritag client SDK (NTAG 424 DNA attestation) — the client half of AttestCore.
Domain-agnostic: nothing here knows what a tag *represents*.

| Package | Path | What |
|---|---|---|
| **Dart / Flutter** | `dart/veritag_sdk/` | ECDSA identity (secure storage), NTAG 424 DNA scan/identify (`GetVersion` gate) + SDM provisioning (EV2, AN12196-validated), `AttestClient` HTTP |
| **TypeScript / Web** | `ts/veritag-sdk/` | WebCrypto identity (non-extractable `CryptoKey` + IndexedDB), `AttestClient` HTTP |
| **Conformance** | `conformance/` | Shared binding vectors — Dart and TS must sign byte-identically |

## Use

Dart (git dependency):

```yaml
dependencies:
  veritag_sdk:
    git:
      url: git@github.com:angesanze/veritag-sdk.git
      path: dart/veritag_sdk
```

TS (checkout + file dependency, the convention `veritag-app` uses):

```json
"@veritag/sdk": "file:../sdk/ts/veritag-sdk"
```

## Test

```bash
cd dart/veritag_sdk && flutter test      # EV2/SDM vectors, identity, conformance
cd ts/veritag-sdk && npm install && npm test
```

No CI here by design: the SDK is a library, consumers (see `veritag-app`) build against it.
