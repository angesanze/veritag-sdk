import 'dart:convert';

import 'package:dna424_client/dna424_client.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// AttestClient HTTP behaviour: non-2xx responses throw AttestApiError, and
/// revokeIssuer hits the right route. Mirrors the TS SDK's attestClient tests.
void main() {
  AttestClient clientReturning(int status, Map<String, dynamic> body,
      {void Function(http.Request)? onRequest}) {
    final mock = MockClient((req) async {
      onRequest?.call(req);
      return http.Response(jsonEncode(body), status,
          headers: {'content-type': 'application/json'});
    });
    return AttestClient('https://x', client: mock);
  }

  test('verify returns the parsed result on 200', () async {
    final c = clientReturning(200, {
      'chip_authentic': true,
      'not_replayed': true,
      'issuer_verified': true,
      'reason': '',
    });
    final r = await c.verify('04D2', 1, 'aa');
    expect(r.fullyValid, isTrue);
  });

  test('non-2xx throws AttestApiError with status + detail', () async {
    final c = clientReturning(400, {'detail': 'm is not valid hex'});
    expect(
      () => c.verify('04D2', 1, 'ZZ'),
      throwsA(isA<AttestApiError>()
          .having((e) => e.status, 'status', 400)
          .having((e) => e.detail, 'detail', contains('not valid hex'))),
    );
  });

  test('registerIssuer returns issuer_id and token', () async {
    final c = clientReturning(200, {'issuer_id': 'iss_abc', 'token': 'isk_x'});
    final reg = await c.registerIssuer('04ab');
    expect(reg.issuerId, equals('iss_abc'));
    expect(reg.token, equals('isk_x'));
  });

  test('revokeIssuer POSTs the revoke route', () async {
    http.Request? seen;
    final c = clientReturning(200, {'issuer_id': 'iss_abc', 'status': 'revoked'},
        onRequest: (r) => seen = r);
    await c.revokeIssuer('iss_abc');
    expect(seen!.method, equals('POST'));
    expect(seen!.url.path, equals('/v1/issuers/iss_abc/revoke'));
  });

  test('revokeIssuer throws on 403', () async {
    final c = clientReturning(403, {'detail': 'cannot revoke another issuer'});
    expect(() => c.revokeIssuer('iss_other'), throwsA(isA<AttestApiError>()));
  });
}
