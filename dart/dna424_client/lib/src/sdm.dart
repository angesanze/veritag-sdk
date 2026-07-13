import 'dart:typed_data';

import 'ev2.dart';

/// NTAG 424 DNA — SDM CMAC (verify side), Dart. Counterpart to the server's
/// crypto/cmac.py and the web SDK's sdm.ts. Lets a mobile app *simulate a tap*:
/// from the short-lived ChipKey it computes the exact CMAC a real chip would
/// mirror into its URL, so the enrol → mint → tap → verify loop runs on the
/// device without an NFC chip. Validated byte-exact against the NXP AN12196
/// vectors (see test/sdm_test.dart).
class Sdm {
  /// The 8-byte SDM CMAC for (uid, readCtr) under chipKey (odd bytes of the CMAC).
  static Uint8List computeSdmCmac(Uint8List chipKey, Uint8List uid, int readCtr) {
    final ctrLe = Uint8List.fromList(
        [readCtr & 0xff, (readCtr >> 8) & 0xff, (readCtr >> 16) & 0xff]);
    final sv2 = Uint8List.fromList(
        [0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80, ...uid, ...ctrLe]);
    final sessionKey = Ev2.aesCmac(chipKey, sv2);
    final mac16 = Ev2.aesCmac(sessionKey, Uint8List(0)); // empty input
    return Uint8List.fromList([for (var i = 1; i < 16; i += 2) mac16[i]]);
  }
}
