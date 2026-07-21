import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import 'ev2.dart';
import 'tag_codec.dart';

/// NTAG 424 DNA tag operations: identification, reading, SDM provisioning.
///
/// Every entry point runs inside ONE reader session ([withArtTag]): a single
/// tap covers identify → read/write → provision, and the session is held until
/// the tag leaves the field so Android never re-dispatches the tag to the OS
/// (that re-dispatch is what used to bounce the user into a browser).
///
/// The chip is identified AUTHORITATIVELY, not by the OS's tag-type label: a
/// genuine NTAG 424 DNA answers the NXP `GetVersion` command with vendor 0x04,
/// type 0x04, storage 0x11. This matters because Android/iOS often report a
/// 424 DNA as `mifare_desfire` (it is EV2-based) — trusting the label falsely
/// rejects real tags. Only that exact silicon is accepted; NTAG 213/215/216,
/// NTAG 413, DESFire and anything else is refused with [NotAnArtTagException].
///
/// All NDEF I/O is raw ISO 7816 (SelectFile + ReadBinary/UpdateBinary on the
/// Type-4 NDEF file E104h) over the same IsoDep channel as the EV2 commands —
/// no tech hand-over mid-session, which is both faster and more reliable than
/// mixing the platform NDEF stack into the flow.
class TagProvisioner {
  TagProvisioner({Random? random}) : _rng = random ?? Random.secure();

  final Random _rng;

  /// AID of the NTAG 424 DNA (NDEF Type 4) application.
  static final Uint8List _aid =
      Uint8List.fromList([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]);

  Future<bool> isAvailable() async =>
      (await FlutterNfcKit.nfcAvailability) == NFCAvailability.available;

  /// Abort a pending [withArtTag] poll (e.g. the user cancelled the overlay).
  Future<void> cancel() async {
    if (_isDesktop) return;
    try {
      await FlutterNfcKit.finish();
    } catch (_) {}
  }

  /// Run [body] against a genuine NTAG 424 DNA inside one reader session.
  ///
  /// Polls for a tag, gates it via `GetVersion` (throws [NotAnArtTagException]
  /// for anything that is not a 424 DNA), hands [body] a live [ArtTagSession],
  /// and — on success — keeps the session open until the tag leaves the field
  /// so the OS never re-reads it behind the app's back.
  Future<T> withArtTag<T>(
    Future<T> Function(ArtTagSession session) body, {
    Duration timeout = const Duration(seconds: 20),
    void Function(String)? onStatus,
  }) async {
    if (_isDesktop) return body(ArtTagSession._sim(this));
    try {
      final tag = await FlutterNfcKit.poll(
          timeout: timeout, androidCheckNDEF: false);
      onStatus?.call('Tag detected — keep the phone still');
      Uint8List version;
      try {
        version = await _getVersion();
      } catch (_) {
        // No NXP GetVersion → not a DESFire/NTAG-4xx chip at all.
        throw NotAnArtTagException(
            'This ${_typeName(tag.type)} tag is not an NTAG 424 DNA.');
      }
      final (is424, model) = identify(version);
      if (!is424) {
        throw NotAnArtTagException('Detected $model — only genuine '
            'NTAG 424 DNA tags are accepted.');
      }
      final session = ArtTagSession._(
          this, tag.id.toUpperCase().replaceAll(':', ''), model);
      final result = await body(session);
      await _waitUntilRemoved(onStatus: onStatus);
      return result;
    } finally {
      try {
        await FlutterNfcKit.finish();
      } catch (_) {}
    }
  }

  /// Tap a tag and report everything we can learn about it — the ground truth
  /// for debugging "it doesn't scan". Never throws: any failure lands in
  /// [NfcDiagnostics.error].
  Future<NfcDiagnostics> diagnose() async {
    if (_isDesktop) {
      return NfcDiagnostics(
        uid: '04D2760000850100', type: 'iso7816 (desktop sim)', standard: '-',
        model: 'NTAG 424 DNA', is424: true, versionHex: '', appSelected: true,
        content: null, error: null,
      );
    }
    try {
      final tag = await FlutterNfcKit.poll(
          timeout: const Duration(seconds: 20), androidCheckNDEF: false);
      String versionHex = '';
      String model = 'unknown';
      bool is424 = false;
      try {
        final v = await _getVersion();
        versionHex = _hexEncode(v);
        (is424, model) = identify(v);
      } catch (e) {
        model = 'no NXP GetVersion (${_short(e)})';
      }
      bool appSelected = false;
      String? appSelectError;
      try {
        await _selectApplication();
        appSelected = true;
      } catch (e) {
        appSelectError = _short(e);
      }
      String? content;
      try {
        final data = parseArtTagFile(await _readNdefFile());
        content = data == null
            ? null
            : data.legacyUrl ??
                'ArtTrust record · uid=${data.uid} ctr=${data.ctr} '
                    'sdm=${data.sdmActive ? "active" : "inactive"}';
      } catch (_) {}
      return NfcDiagnostics(
        uid: tag.id.toUpperCase().replaceAll(':', ''),
        type: _typeName(tag.type), standard: tag.standard, model: model,
        is424: is424, versionHex: versionHex, appSelected: appSelected,
        appSelectError: appSelectError, content: content, error: null,
      );
    } catch (e) {
      return NfcDiagnostics(
        uid: '', type: '', standard: '', model: '', is424: false,
        versionHex: '', appSelected: false, content: null, error: _short(e),
      );
    } finally {
      try {
        await FlutterNfcKit.finish();
      } catch (_) {}
    }
  }

  // -- APDU plumbing -------------------------------------------------------
  Future<Uint8List> _transceive(Uint8List capdu) =>
      FlutterNfcKit.transceive<Uint8List>(capdu);

  /// Split an R-APDU into (data, sw1sw2).
  (Uint8List, int) _split(Uint8List r) {
    final sw = (r[r.length - 2] << 8) | r[r.length - 1];
    return (Uint8List.sublistView(r, 0, r.length - 2), sw);
  }

  /// DESFire/NTAG `GetVersion` (0x60 then 0xAF frames). Returns the
  /// concatenated payload (hardware ‖ software ‖ production). Throws if the tag
  /// doesn't speak the NXP native command set.
  Future<Uint8List> _getVersion() async {
    final out = <int>[];
    var (data, sw) = _split(await _transceive(
        Uint8List.fromList([0x90, 0x60, 0x00, 0x00, 0x00])));
    out.addAll(data);
    var guard = 0;
    while (sw == 0x91AF && guard++ < 4) {
      final r = _split(await _transceive(
          Uint8List.fromList([0x90, 0xAF, 0x00, 0x00, 0x00])));
      out.addAll(r.$1);
      sw = r.$2;
    }
    if (sw != 0x9100) {
      throw StateError('GetVersion sw=${sw.toRadixString(16)}');
    }
    return Uint8List.fromList(out);
  }

  /// (isNtag424Dna, humanLabel) from a GetVersion response's hardware bytes:
  /// [0]=vendor (0x04 NXP), [1]=type (0x04 NTAG), [5]=storage size.
  /// STRICT: only the NTAG 424 DNA (storage 0x11) passes — not 413, not
  /// DESFire, not any other NXP part.
  static (bool, String) identify(Uint8List v) {
    if (v.length < 7) return (false, 'unrecognised card');
    final vendor = v[0], type = v[1], storage = v[5];
    if (vendor != 0x04) {
      return (false, 'non-NXP tag (vendor 0x${_hx(vendor)})');
    }
    if (type != 0x04) {
      return (false, 'NXP DESFire (type 0x${_hx(type)})');
    }
    if (storage == 0x11) return (true, 'NTAG 424 DNA');
    return (
      false,
      storage == 0x0F
          ? 'NTAG 413 DNA'
          : 'NTAG 4xx (storage 0x${_hx(storage)})'
    );
  }

  Future<void> _selectApplication() async {
    final apdu = Uint8List.fromList(
        [0x00, 0xA4, 0x04, 0x00, _aid.length, ..._aid, 0x00]);
    final (_, sw) = _split(await _transceive(apdu));
    if (sw != 0x9000) {
      throw StateError('ISOSelect app failed: sw=${sw.toRadixString(16)}');
    }
  }

  /// ISOSelectFile of the Type-4 NDEF file (ISO FID E104h) inside the app.
  Future<void> _selectNdefFile() async {
    final (_, sw) = _split(await _transceive(
        Uint8List.fromList([0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04])));
    if (sw != 0x9000) {
      throw StateError('ISOSelect NDEF file failed: sw=${sw.toRadixString(16)}');
    }
  }

  /// ISOReadBinary the whole NDEF file (NLEN + message) in one session.
  Future<Uint8List> _readNdefFile() async {
    await _selectApplication();
    await _selectNdefFile();
    Future<Uint8List> read(int off, int len) async {
      final (data, sw) = _split(await _transceive(
          Uint8List.fromList([0x00, 0xB0, (off >> 8) & 0xFF, off & 0xFF, len])));
      if (sw != 0x9000) {
        throw StateError('ReadBinary sw=${sw.toRadixString(16)}');
      }
      return data;
    }

    final head = await read(0, 2);
    final nlen = (head[0] << 8) | head[1];
    final out = <int>[...head];
    var off = 2;
    while (off < 2 + nlen) {
      final chunk = await read(off, (2 + nlen - off).clamp(1, 128));
      if (chunk.isEmpty) break;
      out.addAll(chunk);
      off += chunk.length;
    }
    return Uint8List.fromList(out);
  }

  Future<void> _updateBinary(int off, List<int> data) async {
    final (_, sw) = _split(await _transceive(Uint8List.fromList(
        [0x00, 0xD6, (off >> 8) & 0xFF, off & 0xFF, data.length, ...data])));
    if (sw != 0x9000) {
      throw StateError('UpdateBinary sw=${sw.toRadixString(16)}'
          '${sw == 0x6982 ? " (file locked — tag already provisioned?)" : ""}');
    }
  }

  /// ISOUpdateBinary the NDEF file, power-loss safe: NLEN is zeroed first and
  /// written back last, so a torn write leaves an *empty* file, never garbage.
  Future<void> _writeNdefFile(Uint8List file) async {
    await _selectApplication();
    await _selectNdefFile();
    await _updateBinary(0, const [0x00, 0x00]);
    for (var off = 2; off < file.length; off += 120) {
      await _updateBinary(off, file.sublist(off, min(off + 120, file.length)));
    }
    await _updateBinary(0, file.sublist(0, 2));
  }

  /// Zero the whole NDEF file: length first (so the tag reads as empty from the
  /// very first byte written), then every byte of the body, so nothing of the
  /// old record survives in the chip — not even unreferenced bytes.
  ///
  /// Only works while the file is writable: on a provisioned tag call
  /// [_openNdefFile] over an EV2 session first.
  Future<void> _eraseNdefFile({int size = 256}) async {
    await _selectApplication();
    await _selectNdefFile();
    await _updateBinary(0, const [0x00, 0x00]);
    for (var off = 2; off < size; off += 120) {
      await _updateBinary(off, List<int>.filled(min(120, size - off), 0x00));
    }
  }

  /// Poll the tag with a cheap APDU until it stops answering (left the field).
  /// Keeping the reader session alive here is what prevents Android from
  /// re-dispatching the tag (and its content) to the OS the instant we finish.
  Future<void> _waitUntilRemoved(
      {Duration timeout = const Duration(seconds: 8),
      void Function(String)? onStatus}) async {
    onStatus?.call('Done — you can lift the phone');
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      await Future.delayed(const Duration(milliseconds: 250));
      try {
        await _selectApplication();
      } catch (_) {
        return; // tag gone — session can close with nothing left to dispatch
      }
    }
  }

  /// Full AuthenticateEV2First (Cmd 0x71 then 0xAF). Returns the live session.
  Future<_Ev2Session> _authenticateEv2First(
      {required int keyNo, required Uint8List key}) async {
    final p1 = Uint8List.fromList([0x90, 0x71, 0x00, 0x00, 0x02, keyNo, 0x00, 0x00]);
    final (encRndB, sw1) = _split(await _transceive(p1));
    if (sw1 != 0x91AF) {
      throw StateError('AuthEV2First part1 failed: sw=${sw1.toRadixString(16)}');
    }
    final rndB = Ev2.aesCbcDecrypt(key, encRndB);

    final rndA = _randomBytes(16);
    final challenge =
        Ev2.aesCbcEncrypt(key, Uint8List.fromList([...rndA, ...Ev2.rotateLeft(rndB)]));
    final p2 = Uint8List.fromList(
        [0x90, 0xAF, 0x00, 0x00, challenge.length, ...challenge, 0x00]);
    final (encResp, sw2) = _split(await _transceive(p2));
    if (sw2 != 0x9100) {
      throw StateError('AuthEV2First part2 failed: sw=${sw2.toRadixString(16)}');
    }

    final plain = Ev2.aesCbcDecrypt(key, encResp);
    final ti = Uint8List.sublistView(plain, 0, 4);
    final rndAPrime = Uint8List.sublistView(plain, 4, 20);
    if (!Ev2.verifyRndAPrime(rndA, rndAPrime)) {
      throw StateError('AuthEV2First: card RndA mismatch (wrong Key0?)');
    }

    final keys = Ev2.deriveSessionKeys(key, rndA, rndB);
    return _Ev2Session(sesEnc: keys[0], sesMac: keys[1], ti: ti);
  }

  Future<void> _changeKey(
    _Ev2Session s,
    Uint8List authKey0, {
    required int keyNo,
    required Uint8List newKey,
    required int newVersion,
    Uint8List? oldKey,
  }) async {
    final old = oldKey ?? Uint8List(16);
    final keyData = Uint8List.fromList([
      for (var i = 0; i < 16; i++) newKey[i] ^ old[i],
      newVersion,
      ..._crc32Le(newKey),
    ]);
    final header = Uint8List.fromList([keyNo]);
    final enc = Ev2.encryptCommandData(s.sesEnc, s.ti, s.cmdCtr, keyData);
    final mac = Ev2.commandMac(s.sesMac, 0xC4, s.cmdCtr, s.ti, header, enc);
    final apdu = Uint8List.fromList([
      0x90, 0xC4, 0x00, 0x00,
      header.length + enc.length + mac.length,
      ...header, ...enc, ...mac, 0x00,
    ]);
    final (_, sw) = _split(await _transceive(apdu));
    s.advance();
    if (sw != 0x9100) {
      throw StateError('ChangeKey failed: sw=${sw.toRadixString(16)}'
          '${sw == 0x911E ? " (Key2 is not at factory default — tag was provisioned before?)" : ""}');
    }
  }

  /// ChangeFileSettings (Cmd 0x5F) on the NDEF file (0x02): enable SDM with
  /// plaintext UID + ReadCtr mirroring and a CMAC.
  ///
  /// SDMAccessRights nibbles: RFU=F, CtrRet=F (no GetFileCounters),
  /// MetaRead=E (plaintext mirror), FileRead=2 (Key2 drives the SDM CMAC) —
  /// on the wire byte0=(RFU|CtrRet)=FFh, byte1=(MetaRead|FileRead)=E2h.
  /// With FileRead≠F the chip expects BOTH SDMMACInputOffset and SDMMACOffset;
  /// they are equal here (zero-length MAC input), matching the server's
  /// `compute_sdm_cmac` which MACs the empty string.
  Future<void> _changeFileSettings(
    _Ev2Session s, {
    required int uidOffset,
    required int ctrOffset,
    required int cmacOffset,
  }) async {
    final settings = Uint8List.fromList([
      0x40, // FileOption: SDM enabled, CommMode.PLAIN
      0x00, 0xE0, // AccessRights: Read=free, Write/RW/Change=Key0
      0xC1, // SDMOptions: UID mirror + ReadCtr mirror + ASCII
      0xFF, 0xE2, // SDMAccessRights (see doc comment)
      ..._le24(uidOffset), // UIDOffset
      ..._le24(ctrOffset), // SDMReadCtrOffset
      ..._le24(cmacOffset), // SDMMACInputOffset (== SDMMACOffset: empty input)
      ..._le24(cmacOffset), // SDMMACOffset
    ]);
    final header = Uint8List.fromList([0x02]);
    final enc = Ev2.encryptCommandData(s.sesEnc, s.ti, s.cmdCtr, settings);
    final mac = Ev2.commandMac(s.sesMac, 0x5F, s.cmdCtr, s.ti, header, enc);
    final apdu = Uint8List.fromList([
      0x90, 0x5F, 0x00, 0x00,
      header.length + enc.length + mac.length,
      ...header, ...enc, ...mac, 0x00,
    ]);
    final (_, sw) = _split(await _transceive(apdu));
    s.advance();
    if (sw != 0x9100) {
      throw StateError('ChangeFileSettings failed: sw=${sw.toRadixString(16)}');
    }
  }

  /// Undo [_changeFileSettings]: SDM off, plain comm, and the NDEF file open
  /// for writing again (Read/Write free, RW/Change still Key0). This is what
  /// makes a provisioned tag erasable — after provisioning, Write needs Key0.
  Future<void> _openNdefFile(_Ev2Session s) async {
    final settings = Uint8List.fromList([
      0x00, // FileOption: SDM off, CommMode.PLAIN
      0x00, 0xEE, // AccessRights: Read/Write free, RW/Change = Key0
    ]);
    final header = Uint8List.fromList([0x02]);
    final enc = Ev2.encryptCommandData(s.sesEnc, s.ti, s.cmdCtr, settings);
    final mac = Ev2.commandMac(s.sesMac, 0x5F, s.cmdCtr, s.ti, header, enc);
    final apdu = Uint8List.fromList([
      0x90, 0x5F, 0x00, 0x00,
      header.length + enc.length + mac.length,
      ...header, ...enc, ...mac, 0x00,
    ]);
    final (_, sw) = _split(await _transceive(apdu));
    s.advance();
    if (sw != 0x9100) {
      throw StateError('ChangeFileSettings (reopen) failed: '
          'sw=${sw.toRadixString(16)}');
    }
  }

  // -- small helpers -------------------------------------------------------
  Uint8List _randomBytes(int n) =>
      Uint8List.fromList(List<int>.generate(n, (_) => _rng.nextInt(256)));

  Uint8List _le24(int v) =>
      Uint8List.fromList([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff]);

  /// JAMCRC (CRC-32/JAMCRC) little-endian, as the NTAG 424 expects for ChangeKey.
  Uint8List _crc32Le(Uint8List data) {
    var crc = 0xFFFFFFFF;
    for (final b in data) {
      crc ^= b;
      for (var i = 0; i < 8; i++) {
        crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
      }
    }
    crc &= 0xFFFFFFFF;
    return Uint8List.fromList(
        [crc & 0xff, (crc >> 8) & 0xff, (crc >> 16) & 0xff, (crc >> 24) & 0xff]);
  }

  Uint8List _hexToBytes(String hex) {
    final clean = hex.replaceAll(':', '');
    return Uint8List.fromList([
      for (var i = 0; i < clean.length; i += 2)
        int.parse(clean.substring(i, i + 2), radix: 16)
    ]);
  }

  static String _hx(int b) => b.toRadixString(16).padLeft(2, '0');
  String _hexEncode(List<int> b) => b.map(_hx).join();
  String _typeName(NFCTagType t) => t.toString().split('.').last;
  String _short(Object e) {
    final s = e.toString();
    return s.length > 90 ? '${s.substring(0, 90)}…' : s;
  }

  bool get _isDesktop =>
      Platform.isLinux || Platform.isWindows || Platform.isMacOS;
}

/// A live, gated NTAG 424 DNA on the reader — handed to [TagProvisioner.withArtTag].
class ArtTagSession {
  ArtTagSession._(this._p, this.uid, this.model) : _sim = false;
  ArtTagSession._sim(this._p)
      : uid = '04D2760000850100',
        model = 'NTAG 424 DNA (desktop sim)',
        _sim = true;

  final TagProvisioner _p;
  final bool _sim;

  /// Chip UID (hex, uppercase) — proven 424 DNA silicon.
  final String uid;
  final String model;

  /// Read and parse the tag's NDEF file. Null on a blank tag.
  Future<ArtTagData?> readData() async {
    if (_sim) return null;
    return parseArtTagFile(await _p._readNdefFile());
  }

  /// Provision the tag for Secure Dynamic Messaging: write the ArtTrust data
  /// record, then (over the EV2 secure channel) set Key2 = [chipKeyHex] and
  /// turn on SDM mirroring of UID/ReadCtr/CMAC into it.
  Future<void> provisionSdm({
    required String chipKeyHex,
    Uint8List? authKey0,
    void Function(String)? onStatus,
  }) async {
    final chipKey = _p._hexToBytes(chipKeyHex);
    if (chipKey.length != 16) {
      throw ArgumentError('chipKey must be 16 bytes (AES-128)');
    }
    if (_sim) return;
    final key0 = authKey0 ?? Uint8List(16); // factory default = zeros
    final tpl = buildArtTagFile();

    onStatus?.call('Writing the tag record');
    await _p._writeNdefFile(tpl.file);

    onStatus?.call('Authenticating (EV2, Key0)');
    final session = await _p._authenticateEv2First(keyNo: 0, key: key0);

    onStatus?.call('Setting the chip key (Key2)');
    await _p._changeKey(session, key0, keyNo: 2, newKey: chipKey, newVersion: 1);

    onStatus?.call('Enabling secure mirroring (SDM)');
    await _p._changeFileSettings(session,
        uidOffset: tpl.uidOff, ctrOffset: tpl.ctrOff, cmacOffset: tpl.cmacOff);
  }

  /// Retire this tag: stop the mirroring, reopen the NDEF file and zero it.
  ///
  /// Afterwards the chip carries nothing — no record, no UID/counter/CMAC
  /// mirror — so a phone that meets it sees a blank tag and dispatches nowhere.
  /// This is how a tag written in an older format (a URL record that opened a
  /// browser, say) is taken out of circulation. The silicon and its keys are
  /// left alone: the chip can be provisioned again from scratch.
  Future<void> wipe({
    Uint8List? authKey0,
    void Function(String)? onStatus,
  }) async {
    if (_sim) return;
    // The NDEF application has to be selected before AuthEV2First, or the chip
    // answers 9140 (no such key) — it is looking in the wrong application.
    await _p._selectApplication();

    onStatus?.call('Authenticating (EV2, Key0)');
    final session =
        await _p._authenticateEv2First(keyNo: 0, key: authKey0 ?? Uint8List(16));

    onStatus?.call('Turning off mirroring');
    await _p._openNdefFile(session);

    onStatus?.call('Erasing the record');
    await _p._eraseNdefFile();
  }
}

/// Live EV2 session: keys + transaction id + command counter.
class _Ev2Session {
  _Ev2Session({required this.sesEnc, required this.sesMac, required this.ti});
  final Uint8List sesEnc;
  final Uint8List sesMac;
  final Uint8List ti;
  int cmdCtr = 0;
  void advance() => cmdCtr++;
}

/// Everything a single tap can tell us about a tag — the ground truth behind
/// "it doesn't scan" / "it isn't recognised as a 424".
class NfcDiagnostics {
  NfcDiagnostics({
    required this.uid,
    required this.type,
    required this.standard,
    required this.model,
    required this.is424,
    required this.versionHex,
    required this.appSelected,
    required this.content,
    required this.error,
    this.appSelectError,
  });

  final String uid;          // chip UID (hex)
  final String type;         // the OS tag-type label (iso7816 / mifare_desfire / …)
  final String standard;     // e.g. ISO 14443-4
  final String model;        // what GetVersion says it is
  final bool is424;          // recognised as a genuine NTAG 424 DNA
  final String versionHex;   // raw GetVersion bytes (hex), '' if none
  final bool appSelected;    // did the NDEF/424 application select?
  final String? appSelectError;
  final String? content;     // what the NDEF file holds (record / legacy URL)
  final String? error;       // poll/read failure, if the whole thing failed
}

/// Thrown when a scanned tag is not a genuine NTAG 424 DNA — the device
/// authorizes only 424 DNA silicon for minting and verification.
class NotAnArtTagException implements Exception {
  const NotAnArtTagException(this.message);
  final String message;
  @override
  String toString() => message;
}
