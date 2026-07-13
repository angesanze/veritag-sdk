import 'package:shared_preferences/shared_preferences.dart';

/// Abstraction over private-key storage so the identity layer is decoupled
/// from *where* the key lives.
///
/// Phase 3 status: [SecureKeyStore] (Keychain / Keystore / StrongBox, via
/// flutter_secure_storage) is the production implementation — encrypted at rest,
/// hardware-protected. [SharedPrefsKeyStore] below remains only as the
/// documented-insecure fallback (plaintext, exportable — inherited from ArtTrust
/// 1.0). The endgame is hardware signing with a non-exportable key (Secure
/// Enclave / StrongBox attested key) so the raw key never enters Dart at all.
abstract class KeyStore {
  Future<bool> hasKey();
  Future<String?> privateKeyHex();
  Future<void> savePrivateKeyHex(String hex);

  /// Delete the stored key (rotation / revocation). Irreversible — recovery is
  /// re-enrollment of a fresh identity, never raw-key restore.
  Future<void> deleteKey();
}

class SharedPrefsKeyStore implements KeyStore {
  static const _k = 'dna424_private_key_hex';

  @override
  Future<bool> hasKey() async =>
      (await SharedPreferences.getInstance()).containsKey(_k);

  @override
  Future<String?> privateKeyHex() async =>
      (await SharedPreferences.getInstance()).getString(_k);

  @override
  Future<void> savePrivateKeyHex(String hex) async =>
      (await SharedPreferences.getInstance()).setString(_k, hex);

  @override
  Future<void> deleteKey() async =>
      (await SharedPreferences.getInstance()).remove(_k);
}
