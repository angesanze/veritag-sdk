import 'dart:typed_data';

/// NTAG 424 DNA APDU framing — the low-level command building blocks.
///
/// This holds only the deterministic *command framing* (CLA/INS/P1/P2/Lc/data/Le).
/// The live secure-channel flow — AuthenticateEV2First, then ChangeKey /
/// ChangeFileSettings MAC'd & encrypted under the session keys — is implemented
/// in [TagProvisioner] using [Ev2]; these helpers exist for callers that want to
/// frame individual commands themselves. The EV2 session crypto is validated
/// against the NXP AN12196 vectors (see test/ev2_test.dart).
///
/// Reference: NXP NT4H2421Gx datasheet + AN12196.
class Ntag424Apdu {
  /// ISOSelect the NTAG 424 DNA application (AID D2 76 00 00 85 01 01).
  static Uint8Array isoSelectApplication() => _apdu(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: Uint8List.fromList(
            [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]),
        le: 0x00,
      );

  /// First half of AuthenticateEV2First: send the key number, receive E(RndB).
  /// [TagProvisioner] drives the full RndA/RndB exchange + session-key derivation.
  static Uint8Array authenticateEv2FirstPart1(int keyNo) => _apdu(
        cla: 0x90,
        ins: 0x71,
        p1: 0x00,
        p2: 0x00,
        data: Uint8List.fromList([keyNo, 0x00]),
        le: 0x00,
      );

  /// ChangeKey (INS 0xC4) framing. [cryptogram] is the EV2-session-encrypted new
  /// key (newKey⊕oldKey + version + CRC32), prepared by [TagProvisioner]/[Ev2];
  /// this only frames the already-built cryptogram.
  static Uint8Array changeKey(int keyNo, Uint8List cryptogram) => _apdu(
        cla: 0x90,
        ins: 0xC4,
        p1: 0x00,
        p2: 0x00,
        data: Uint8List.fromList([keyNo, ...cryptogram]),
        le: 0x00,
      );

  /// ChangeFileSettings (INS 0x5F) framing for the NDEF file — carries the SDM
  /// template (enable SDM, UID/ReadCtr/CMAC mirror offsets). The [settings] blob
  /// is built + session-encrypted by [TagProvisioner]/[Ev2].
  static Uint8Array changeFileSettings(int fileNo, Uint8List settings) => _apdu(
        cla: 0x90,
        ins: 0x5F,
        p1: 0x00,
        p2: 0x00,
        data: Uint8List.fromList([fileNo, ...settings]),
        le: 0x00,
      );

  static Uint8Array _apdu({
    required int cla,
    required int ins,
    required int p1,
    required int p2,
    required Uint8List data,
    int? le,
  }) {
    final b = BytesBuilder();
    b.add([cla, ins, p1, p2, data.length]);
    b.add(data);
    if (le != null) b.addByte(le);
    return b.toBytes();
  }
}

/// Alias to keep call sites readable; NTAG APDUs are plain byte buffers.
typedef Uint8Array = Uint8List;
