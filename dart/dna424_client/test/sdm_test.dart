import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dna424_client/dna424_client.dart';
import 'package:test/test.dart';

/// SDM-CMAC validated against the official NXP AN12196 vectors — the same ones
/// that pin crypto/cmac.py and the TS SDK. If these pass, a tag "tapped" on the
/// device produces exactly the CMAC the server expects.
void main() {
  Uint8List h(String s) => Uint8List.fromList(hex.decode(s));

  test('computeSdmCmac matches the AN12196 vectors', () {
    expect(
      hex.encode(Sdm.computeSdmCmac(h('00000000000000000000000000000000'), h('04DE5F1EACC040'), 61)),
      equals('94eed9ee65337086'),
    );
    expect(
      hex.encode(Sdm.computeSdmCmac(h('00000000000000000000000000000000'), h('041E3C8A2D6B80'), 6)),
      equals('4b00064004b0b3d3'),
    );
  });
}
