import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:veritag_sdk/veritag_sdk.dart';
import 'package:test/test.dart';

Uint8List h(String s) => Uint8List.fromList(hex.decode(s));

void main() {
  // Official NXP AN12196 AuthenticateEV2First worked example (K0 = all zeros).
  // Same vector validated byte-exact in attestcore/tests/test_ev2.py.
  final key0 = h('00000000000000000000000000000000');
  final encRndB = h('A04C124213C186F22399D33AC2A30215');
  final rndB = h('B9E2FC789B64BF237CCCAA20EC7E6E48');
  final rndA = h('13C5DB8A5930439FC3DEF9A4C675360F');
  final sesEnc = h('1309C877509E5A215007FF0ED19CA564');
  final sesMac = h('4C6626F5E72EA694202139295C7A7FC7');

  test('AN12196: RndB decrypts (AES-CBC, IV=0)', () {
    expect(Ev2.aesCbcDecrypt(key0, encRndB), equals(rndB));
  });

  test('AN12196: session keys derive byte-exact', () {
    final keys = Ev2.deriveSessionKeys(key0, rndA, rndB);
    expect(keys[0], equals(sesEnc)); // SesAuthENCKey
    expect(keys[1], equals(sesMac)); // SesAuthMACKey
  });

  test('RndA prime is rotate-left of RndA', () {
    expect(Ev2.rotateLeft(rndA), equals(h('C5DB8A5930439FC3DEF9A4C675360F13')));
    expect(Ev2.verifyRndAPrime(rndA, Ev2.rotateLeft(rndA)), isTrue);
    expect(Ev2.verifyRndAPrime(rndA, rndA), isFalse);
  });

  test('command IV is deterministic and counter-dependent', () {
    final ti = h('9D00C4DF');
    expect(Ev2.commandIv(sesEnc, ti, 0), equals(Ev2.commandIv(sesEnc, ti, 0)));
    expect(Ev2.commandIv(sesEnc, ti, 0), isNot(equals(Ev2.commandIv(sesEnc, ti, 1))));
  });
}
