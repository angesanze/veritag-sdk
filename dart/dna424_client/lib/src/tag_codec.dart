/// ArtTrust NDEF layout for the NTAG 424 DNA — pure Dart, no NFC plugin, so the
/// byte layout and the SDM mirror offsets are unit-testable off-device.
///
/// The tag carries ONE NDEF record of NFC-Forum EXTERNAL type
/// (`urn:nfc:ext:arttrust.com:t`) whose ASCII payload is
///
///     v1;u=<14 hex>;c=<6 hex>;m=<16 hex>
///
/// `u`/`c`/`m` are written zero-filled; once SDM is enabled the chip mirrors
/// UID / ReadCtr / CMAC into them (uppercase hex ASCII) fresh on every read.
///
/// An external-type record is deliberately NOT a URI: no OS treats it as a
/// link, so tapping the tag never opens a browser. On Android it dispatches to
/// the ArtTrust app (manifest intent filter) or, without the app, does nothing.
library tag_codec;

import 'dart:convert';
import 'dart:typed_data';

/// NFC-Forum external type carried by ArtTrust tags (domain:name, lowercase).
const String artTagType = 'arttrust.com:t';

const String _uidZeros = '00000000000000'; //  7-byte UID  → 14 hex chars
const String _ctrZeros = '000000'; //          3-byte ctr  →  6 hex chars
const String _cmacZeros = '0000000000000000'; // 8-byte MAC → 16 hex chars

/// The exact bytes of the tag's NDEF *file* (2-byte NLEN + message) plus the
/// byte offsets — relative to the start of the file, as ChangeFileSettings
/// expects — where the chip must mirror UID, ReadCtr and CMAC.
class ArtTagTemplate {
  const ArtTagTemplate(this.file, this.uidOff, this.ctrOff, this.cmacOff);
  final Uint8List file;
  final int uidOff;
  final int ctrOff;
  final int cmacOff;
}

/// Build the NDEF file for a fresh ArtTrust tag.
///
/// Record layout (single short record, so offsets are exact):
///   NLEN(2, big-endian) · flags D4h (MB|ME|SR|TNF=external) · typeLen ·
///   payloadLen · type · payload
ArtTagTemplate buildArtTagFile() {
  const payload = 'v1;u=$_uidZeros;c=$_ctrZeros;m=$_cmacZeros';
  final type = ascii.encode(artTagType);
  final payloadBytes = ascii.encode(payload);
  assert(payloadBytes.length < 0xFF && type.length < 0xFF);

  final record = <int>[
    0xD4, // MB | ME | SR | TNF=4 (external)
    type.length,
    payloadBytes.length,
    ...type,
    ...payloadBytes,
  ];
  final file = Uint8List.fromList(
      [(record.length >> 8) & 0xFF, record.length & 0xFF, ...record]);

  final payloadStart = 2 + 3 + type.length;
  final uidAt = payload.indexOf(_uidZeros);
  return ArtTagTemplate(
    file,
    payloadStart + uidAt,
    payloadStart + uidAt + _uidZeros.length + ';c='.length,
    payloadStart + payload.indexOf(_cmacZeros),
  );
}

/// What a tap recovered from the tag's NDEF file.
class ArtTagData {
  const ArtTagData({this.uid, this.ctr = 0, this.cmacHex = '', this.legacyUrl});

  /// Mirrored UID (14 hex chars), null on a legacy-URL or unreadable tag.
  final String? uid;

  /// Mirrored SDM read counter (parsed from its hex ASCII mirror).
  final int ctr;

  /// Mirrored 8-byte CMAC, hex. All-zeros means SDM is not (yet) active.
  final String cmacHex;

  /// URL found on a tag written by the old URI-record flow, if any.
  final String? legacyUrl;

  /// True when the chip actually mirrored a CMAC (SDM enabled and working).
  bool get sdmActive =>
      cmacHex.isNotEmpty && cmacHex.replaceAll('0', '').isNotEmpty;
}

/// Parse an ArtTrust record payload (`v1;u=…;c=…;m=…`). Returns null if the
/// payload is not ours. The `c` mirror is hex ASCII — parsed radix 16.
ArtTagData? parseArtTagPayload(String payload) {
  final parts = payload.split(';');
  if (parts.isEmpty || parts.first != 'v1') return null;
  String? u, c, m;
  for (final p in parts.skip(1)) {
    final eq = p.indexOf('=');
    if (eq <= 0) continue;
    switch (p.substring(0, eq)) {
      case 'u':
        u = p.substring(eq + 1);
      case 'c':
        c = p.substring(eq + 1);
      case 'm':
        m = p.substring(eq + 1);
    }
  }
  if (u == null || m == null) return null;
  return ArtTagData(
    uid: u.toUpperCase(),
    ctr: int.tryParse(c ?? '0', radix: 16) ?? 0,
    cmacHex: m.toLowerCase(),
  );
}

/// NFC-Forum URI RTD abbreviation table (the subset legacy tags used).
const Map<int, String> _uriPrefixes = {
  0x00: '', 0x01: 'http://www.', 0x02: 'https://www.',
  0x03: 'http://', 0x04: 'https://',
};

/// Parse a raw NDEF *file* (NLEN + message) read straight off the chip.
/// Recognises the ArtTrust external record; falls back to a legacy URI record.
/// Returns null for an empty/blank/foreign file.
ArtTagData? parseArtTagFile(Uint8List file) {
  if (file.length < 2) return null;
  final nlen = (file[0] << 8) | file[1];
  if (nlen == 0 || file.length < 2 + nlen) return null;
  final msg = Uint8List.sublistView(file, 2, 2 + nlen);

  for (final r in _records(msg)) {
    if (r.tnf == 0x04 && r.type == artTagType) {
      final parsed = parseArtTagPayload(ascii.decode(r.payload, allowInvalid: true));
      if (parsed != null) return parsed;
    }
    if (r.tnf == 0x01 && r.type == 'U' && r.payload.isNotEmpty) {
      final prefix = _uriPrefixes[r.payload[0]] ?? '';
      return ArtTagData(
        legacyUrl:
            prefix + utf8.decode(r.payload.sublist(1), allowMalformed: true),
      );
    }
  }
  return null;
}

/// Minimal NDEF message walk: (tnf, type, payload) per record. Handles short
/// and long records and skips ID fields; stops on malformed input.
Iterable<({int tnf, String type, Uint8List payload})> _records(
    Uint8List msg) sync* {
  var i = 0;
  while (i < msg.length) {
    final flags = msg[i];
    final sr = flags & 0x10 != 0, il = flags & 0x08 != 0;
    var p = i + 1;
    if (p >= msg.length) return;
    final typeLen = msg[p++];
    if (p + (sr ? 1 : 4) > msg.length) return;
    var payloadLen = 0;
    if (sr) {
      payloadLen = msg[p++];
    } else {
      payloadLen = (msg[p] << 24) | (msg[p + 1] << 16) | (msg[p + 2] << 8) | msg[p + 3];
      p += 4;
    }
    final idLen = il ? (p < msg.length ? msg[p++] : 0) : 0;
    if (p + typeLen + idLen + payloadLen > msg.length) return;
    final type = ascii.decode(msg.sublist(p, p + typeLen), allowInvalid: true);
    p += typeLen + idLen;
    yield (
      tnf: flags & 0x07,
      type: type,
      payload: Uint8List.sublistView(msg, p, p + payloadLen),
    );
    p += payloadLen;
    if (flags & 0x40 != 0) return; // ME — last record
    i = p;
  }
}
