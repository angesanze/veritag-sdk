# veritag-sdk

Embeddable client SDK for the 424 DNA ecosystem — the client half of AttestCore.
Domain-agnostic: nothing here knows what a tag *represents*.

| Package | Path | What |
|---|---|---|
| **Dart / Flutter** | `dart/dna424_client/` | ECDSA identity (secure storage), NTAG 424 DNA scan/identify (`GetVersion` gate) + SDM provisioning (EV2, AN12196-validated), `AttestClient` HTTP |
| **TypeScript / Web** | `ts/dna424-client/` | WebCrypto identity (non-extractable `CryptoKey` + IndexedDB), `AttestClient` HTTP |
| **Conformance** | `conformance/` | Shared binding vectors — Dart and TS must sign byte-identically |

## Use

Dart (git dependency):

```yaml
dependencies:
  dna424_client:
    git:
      url: git@github.com:angesanze/veritag-sdk.git
      path: dart/dna424_client
```

TS (checkout + file dependency, the convention `veritag-app` uses):

```json
"@dna424/client": "file:../sdk/ts/dna424-client"
```

## Test

```bash
cd dart/dna424_client && flutter test      # EV2/SDM vectors, identity, conformance
cd ts/dna424-client && npm install && npm test
```

No CI here by design: the SDK is a library, consumers (see `veritag-app`) build against it.
