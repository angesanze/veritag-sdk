import 'dart:convert';
import 'dart:typed_data';

import 'package:dna424_client/src/tag_codec.dart';
import 'package:test/test.dart';

void main() {
  test('template layout: single external short record, exact offsets', () {
    final t = buildArtTagFile();
    final f = t.file;
    final nlen = (f[0] << 8) | f[1];
    expect(nlen, f.length - 2);
    expect(f[2], 0xD4); // MB|ME|SR|TNF=external
    expect(f[3], artTagType.length);
    expect(ascii.decode(f.sublist(5, 5 + f[3])), artTagType);

    // Each mirror slot must be exactly its zero-fill, at the declared offset.
    String at(int off, int len) => ascii.decode(f.sublist(off, off + len));
    expect(at(t.uidOff, 14), '0' * 14);
    expect(at(t.ctrOff, 6), '0' * 6);
    expect(at(t.cmacOff, 16), '0' * 16);
    // And the labels sit right before them, proving nothing shifted.
    expect(at(t.uidOff - 2, 2), 'u=');
    expect(at(t.ctrOff - 2, 2), 'c=');
    expect(at(t.cmacOff - 2, 2), 'm=');
  });

  test('roundtrip: simulated SDM mirror parses back to u/c/m', () {
    final t = buildArtTagFile();
    final f = Uint8List.fromList(t.file);
    void put(int off, String s) => f.setRange(off, off + s.length, ascii.encode(s));
    put(t.uidOff, '04AABBCCDD8090');
    put(t.ctrOff, '00000A'); // ReadCtr mirrors as HEX ascii
    put(t.cmacOff, '94EED9EE65337086');

    final d = parseArtTagFile(f)!;
    expect(d.uid, '04AABBCCDD8090');
    expect(d.ctr, 10); // parsed radix 16
    expect(d.cmacHex, '94eed9ee65337086');
    expect(d.sdmActive, isTrue);
    expect(d.legacyUrl, isNull);
  });

  test('freshly written (unmirrored) tag is not sdmActive', () {
    final d = parseArtTagFile(buildArtTagFile().file)!;
    expect(d.sdmActive, isFalse);
    expect(d.ctr, 0);
  });

  test('legacy URI record still readable', () {
    const url = 'example.com/t/04AABB';
    final payload = [0x04, ...ascii.encode(url)]; // 0x04 = 'https://'
    final record = [0xD1, 1, payload.length, 0x55, ...payload];
    final file = Uint8List.fromList(
        [(record.length >> 8) & 0xFF, record.length & 0xFF, ...record]);
    final d = parseArtTagFile(file)!;
    expect(d.legacyUrl, 'https://$url');
    expect(d.sdmActive, isFalse);
  });

  test('blank, foreign and malformed files parse to null', () {
    expect(parseArtTagFile(Uint8List.fromList([0, 0])), isNull);
    expect(parseArtTagFile(Uint8List(0)), isNull);
    // text record — not ours
    final rec = [0xD1, 1, 3, 0x54, 0x02, 0x65, 0x6E];
    expect(
        parseArtTagFile(Uint8List.fromList([0, rec.length, ...rec])), isNull);
    // truncated: NLEN says more bytes than present
    expect(parseArtTagFile(Uint8List.fromList([0, 60, 0xD4, 1])), isNull);
  });

  test('payload parser (intent path) matches file parser', () {
    final d = parseArtTagPayload('v1;u=04aabbccdd8090;c=0000ff;m=AABBCCDDEEFF0011')!;
    expect(d.uid, '04AABBCCDD8090');
    expect(d.ctr, 255);
    expect(d.cmacHex, 'aabbccddeeff0011');
    expect(parseArtTagPayload('v2;u=x'), isNull);
    expect(parseArtTagPayload('hello'), isNull);
  });
}
