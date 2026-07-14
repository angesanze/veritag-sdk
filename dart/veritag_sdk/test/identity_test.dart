import 'package:convert/convert.dart';
import 'package:veritag_sdk/veritag_sdk.dart';
import 'package:test/test.dart';

/// In-memory KeyStore so identity tests don't need a device/secure store.
class _MemKeyStore implements KeyStore {
  String? _hex;
  @override
  Future<bool> hasKey() async => _hex != null;
  @override
  Future<String?> privateKeyHex() async => _hex;
  @override
  Future<void> savePrivateKeyHex(String hex) async => _hex = hex;
  @override
  Future<void> deleteKey() async => _hex = null;
}

void main() {
  test('createIdentity persists and publicKeyHex is stable', () async {
    final svc = IdentityService(_MemKeyStore());
    expect(await svc.hasIdentity(), isFalse);
    final pub = await svc.createIdentity();
    expect(await svc.hasIdentity(), isTrue);
    expect(pub, isNotEmpty);
    expect(await svc.publicKeyHex(), equals(pub));
  });

  test('buildAndSign returns an opaque payload + DER signature', () async {
    final svc = IdentityService(_MemKeyStore());
    await svc.createIdentity();
    final bs = await svc.buildAndSign('04D2760000850100', 'some-context');
    expect(bs, isNotNull);
    // payload is a SHA-256 digest => 32 bytes hex
    expect(hex.decode(bs!.payloadHex).length, equals(32));
    // DER signature decodes and starts with the SEQUENCE tag 0x30
    final der = hex.decode(bs.signatureHex);
    expect(der.first, equals(0x30));
  });

  test('rotateIdentity replaces the key; deleteIdentity clears it', () async {
    final svc = IdentityService(_MemKeyStore());
    final pub1 = await svc.createIdentity();
    final pub2 = await svc.rotateIdentity();
    expect(pub2, isNot(equals(pub1)));            // fresh key
    expect(await svc.publicKeyHex(), equals(pub2)); // store holds the new one

    await svc.deleteIdentity();
    expect(await svc.hasIdentity(), isFalse);
  });
}
