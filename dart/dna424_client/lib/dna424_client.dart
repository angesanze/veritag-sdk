/// dna424_client — embeddable client SDK for the 424 DNA ecosystem.
///
/// Three pieces, mirroring the server core:
///   - IdentityService : P-256 keypair + opaque binding signing (issuer side)
///   - TagProvisioner   : NTAG 424 DNA scan + SDM provisioning
///   - AttestClient     : HTTP to the AttestCore web API (provision / verify)
///
/// Domain-agnostic by design: nothing here mentions "art". An app supplies the
/// binding context; the SDK signs and provisions; the server attests.
library dna424_client;

export 'src/identity_service.dart';
export 'src/key_store.dart';
export 'src/secure_key_store.dart';
export 'src/attest_client.dart';
export 'src/tag_provisioner.dart';
export 'src/tag_codec.dart';
export 'src/apdu.dart';
export 'src/ev2.dart';
export 'src/sdm.dart';
