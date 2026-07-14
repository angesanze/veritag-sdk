import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'key_store.dart';

/// Phase 3 KeyStore backed by the platform secure store: Keychain (iOS) and
/// Keystore/StrongBox (Android), via flutter_secure_storage. This replaces
/// [SharedPrefsKeyStore], which kept the raw private key in plaintext
/// SharedPreferences (inherited from ArtTrust 1.0 — see DEVELOPMENT_PLAN §5).
///
/// LIMITATION (still Phase 3): the private key is stored as hex and read back
/// into Dart to sign. That is strictly better than SharedPreferences (encrypted
/// at rest, hardware-protected) but the key is still *exportable into process
/// memory*. The endgame is signing INSIDE the secure element with a
/// non-exportable key (Secure Enclave / StrongBox attested key) so the raw key
/// never enters Dart at all — tracked as the Phase 3 hardware-signing TODO.
class SecureKeyStore implements KeyStore {
  SecureKeyStore({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  static const _k = 'dna424_private_key_hex';
  final FlutterSecureStorage _storage;

  @override
  Future<bool> hasKey() async => (await _storage.read(key: _k)) != null;

  @override
  Future<String?> privateKeyHex() => _storage.read(key: _k);

  @override
  Future<void> savePrivateKeyHex(String hex) =>
      _storage.write(key: _k, value: hex);

  @override
  Future<void> deleteKey() => _storage.delete(key: _k);
}
