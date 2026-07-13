import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:dna424_client/dna424_client.dart';
import 'package:test/test.dart';

/// Cross-SDK conformance: buildBinding must match the shared vectors (and thus
/// the TS SDK and the Python reference). See sdk/conformance/binding_vectors.json.
void main() {
  test('buildBinding matches the shared conformance vectors', () {
    // test/ -> dna424_client -> dart -> sdk/conformance
    final file = File('${Directory.current.path}/../../conformance/binding_vectors.json');
    final data = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    for (final v in data['vectors'] as List) {
      final got = hex.encode(buildBinding(v['uid'] as String, v['context'] as String));
      expect(got, equals(v['binding_hex']),
          reason: 'binding for ${v['uid']}|${v['context']}');
    }
  });
}
