import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// NTAG 424 DNA — EV2 secure channel (provisioning side).
///
/// Faithful Dart port of the validated reference `attestcore/crypto/ev2.py`.
/// The session-key derivation is byte-exact against the official NXP AN12196
/// AuthenticateEV2First worked example (see test/ev2_test.dart). ArtTrust 1.0
/// mocked all of this ("auth skipped for the demo"); here it is real crypto.
///
///     SV1 = A5 5A 00 01 00 80 || RndA[0:2] || (RndA[2:8] ^ RndB[0:6])
///                              || RndB[6:16] || RndA[8:16]
///     SV2 = 5A A5 00 01 00 80 || (same tail)
///     SesAuthENCKey = CMAC(K, SV1)
///     SesAuthMACKey = CMAC(K, SV2)
class Ev2 {
  static final Uint8List _zeroIv = Uint8List(16);

  // -- AES-CBC -------------------------------------------------------------
  static Uint8List aesCbcEncrypt(Uint8List key, Uint8List data, [Uint8List? iv]) =>
      _cbc(true, key, data, iv ?? _zeroIv);

  static Uint8List aesCbcDecrypt(Uint8List key, Uint8List data, [Uint8List? iv]) =>
      _cbc(false, key, data, iv ?? _zeroIv);

  static Uint8List _cbc(bool encrypt, Uint8List key, Uint8List data, Uint8List iv) {
    final c = CBCBlockCipher(AESEngine())
      ..init(encrypt, ParametersWithIV(KeyParameter(key), iv));
    final out = Uint8List(data.length);
    for (var off = 0; off < data.length; off += 16) {
      c.processBlock(data, off, out, off);
    }
    return out;
  }

  static Uint8List _aesEcbBlock(Uint8List key, Uint8List block) {
    final c = AESEngine()..init(true, KeyParameter(key));
    final out = Uint8List(16);
    c.processBlock(block, 0, out, 0);
    return out;
  }

  // -- AES-CMAC ------------------------------------------------------------
  static Uint8List aesCmac(Uint8List key, Uint8List msg) {
    final mac = CMac(AESEngine(), 128)..init(KeyParameter(key));
    return mac.process(msg);
  }

  // -- Helpers -------------------------------------------------------------
  static Uint8List rotateLeft(Uint8List b) =>
      Uint8List.fromList([...b.sublist(1), b[0]]);

  static Uint8List _sessionVector(List<int> prefix, Uint8List a, Uint8List b) {
    if (a.length != 16 || b.length != 16) {
      throw ArgumentError('RndA and RndB must be 16 bytes');
    }
    final xored = List<int>.generate(6, (i) => a[2 + i] ^ b[i]);
    return Uint8List.fromList([
      ...prefix,
      ...a.sublist(0, 2),
      ...xored,
      ...b.sublist(6, 16),
      ...a.sublist(8, 16),
    ]);
  }

  /// Returns [SesAuthENCKey, SesAuthMACKey].
  static List<Uint8List> deriveSessionKeys(Uint8List key, Uint8List rndA, Uint8List rndB) {
    final sv1 = _sessionVector(const [0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80], rndA, rndB);
    final sv2 = _sessionVector(const [0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80], rndA, rndB);
    return [aesCmac(key, sv1), aesCmac(key, sv2)];
  }

  static bool verifyRndAPrime(Uint8List rndA, Uint8List rndAPrime) {
    final r = rotateLeft(rndA);
    if (r.length != rndAPrime.length) return false;
    for (var i = 0; i < r.length; i++) {
      if (r[i] != rndAPrime[i]) return false;
    }
    return true;
  }

  // -- EV2 secure messaging (CommMode.FULL) --------------------------------
  static Uint8List _le16(int v) => Uint8List.fromList([v & 0xff, (v >> 8) & 0xff]);

  static Uint8List commandIv(Uint8List sesEnc, Uint8List ti, int cmdCtr) =>
      _aesEcbBlock(sesEnc,
          Uint8List.fromList([0xA5, 0x5A, ...ti, ..._le16(cmdCtr), ...List.filled(8, 0)]));

  static Uint8List responseIv(Uint8List sesEnc, Uint8List ti, int cmdCtr) =>
      _aesEcbBlock(sesEnc,
          Uint8List.fromList([0x5A, 0xA5, ...ti, ..._le16(cmdCtr), ...List.filled(8, 0)]));

  static Uint8List _padM2(Uint8List data) {
    final out = <int>[...data, 0x80];
    while (out.length % 16 != 0) {
      out.add(0x00);
    }
    return Uint8List.fromList(out);
  }

  static Uint8List encryptCommandData(
      Uint8List sesEnc, Uint8List ti, int cmdCtr, Uint8List plain) {
    return aesCbcEncrypt(sesEnc, _padM2(plain), commandIv(sesEnc, ti, cmdCtr));
  }

  /// 8-byte EV2 command MAC: even bytes of CMAC(SesMAC, Cmd||CmdCtr||TI||Hdr||Data).
  static Uint8List commandMac(Uint8List sesMac, int cmd, int cmdCtr, Uint8List ti,
      Uint8List header, Uint8List encData) {
    final msg = Uint8List.fromList(
        [cmd, ..._le16(cmdCtr), ...ti, ...header, ...encData]);
    final full = aesCmac(sesMac, msg);
    return Uint8List.fromList([for (var i = 1; i < 16; i += 2) full[i]]);
  }
}
