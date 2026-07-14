import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:elliptic/elliptic.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:crypto/crypto.dart';

import 'key_store.dart';

/// Holds the issuer/creator identity: a P-256 keypair whose private key never
/// leaves the device. Signs OPAQUE binding payloads — it does not know or care
/// what the payload means (artwork, document, batch...).
///
/// This is the client half of the attestation core, extracted from ArtTrust
/// 1.0's `CryptoService` and made domain-agnostic.
class IdentityService {
  IdentityService(this._store);

  final KeyStore _store;
  final _curve = getP256();

  Future<bool> hasIdentity() => _store.hasKey();

  /// Create a new identity. Returns the uncompressed public key hex (04||X||Y)
  /// to register with the AttestCore issuer registry.
  Future<String> createIdentity() async {
    final priv = _curve.generatePrivateKey();
    await _store.savePrivateKeyHex(priv.toHex());
    return priv.publicKey.toHex();
  }

  Future<String?> publicKeyHex() async {
    final hexKey = await _store.privateKeyHex();
    if (hexKey == null) return null;
    return PrivateKey.fromHex(_curve, hexKey).publicKey.toHex();
  }

  /// Rotate the identity: generate a fresh key, replace the stored one, and
  /// return the new public key hex. The previous key is irrecoverable by design
  /// — recovery is re-enrollment of the new public key with the issuer registry
  /// (and revocation of the old issuer id), never a raw-key restore.
  Future<String> rotateIdentity() async {
    final priv = _curve.generatePrivateKey();
    await _store.savePrivateKeyHex(priv.toHex());
    return priv.publicKey.toHex();
  }

  /// Delete the identity (e.g. on logout / device wipe).
  Future<void> deleteIdentity() => _store.deleteKey();

  /// Sign an opaque binding payload (raw bytes). Returns DER hex.
  Future<String?> signBinding(List<int> bindingPayload) async {
    final hexKey = await _store.privateKeyHex();
    if (hexKey == null) return null;
    final priv = PrivateKey.fromHex(_curve, hexKey);
    final digest = sha256.convert(bindingPayload).bytes;
    final sig = signature(priv, digest);
    return hex.encode(sig.toDER());
  }

  /// Convenience: build the binding payload the way a consumer chooses, then
  /// sign it. The default scheme is SHA-256(uid || '|' || context).
  Future<BindingSignature?> buildAndSign(String uid, String context) async {
    final payload = buildBinding(uid, context);
    final der = await signBinding(payload);
    if (der == null) return null;
    return BindingSignature(payloadHex: hex.encode(payload), signatureHex: der);
  }
}

/// The default opaque binding: SHA-256(utf8(uid + '|' + context)).
///
/// MUST stay byte-identical to the TS SDK's `buildBinding` — both are pinned by
/// sdk/conformance/binding_vectors.json. Drift here breaks cross-SDK signatures.
List<int> buildBinding(String uid, String context) =>
    sha256.convert(utf8.encode('$uid|$context')).bytes;

class BindingSignature {
  BindingSignature({required this.payloadHex, required this.signatureHex});
  final String payloadHex;
  final String signatureHex;
}
