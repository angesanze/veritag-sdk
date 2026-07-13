import 'dart:convert';
import 'package:http/http.dart' as http;

/// Thrown on any non-2xx response, carrying the status and the API's detail.
class AttestApiError implements Exception {
  AttestApiError(this.status, this.detail);
  final int status;
  final String detail;
  @override
  String toString() => 'AttestCore $status: $detail';
}

/// Thin HTTP client for the AttestCore web API. Used by any app in the
/// ecosystem to provision tags and verify scans. Domain-agnostic.
class AttestClient {
  AttestClient(this.baseUrl, {this.bearerToken, http.Client? client})
      : _http = client ?? http.Client();

  final String baseUrl;
  final String? bearerToken;
  final http.Client _http;

  Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (bearerToken != null) 'Authorization': 'Bearer $bearerToken',
      };

  /// Decode a response, throwing [AttestApiError] on non-2xx instead of casting
  /// an error body to a success type.
  Map<String, dynamic> _parse(http.Response r) {
    final body = r.body.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(r.body) as Map<String, dynamic>;
    if (r.statusCode ~/ 100 != 2) {
      throw AttestApiError(r.statusCode, (body['detail'] ?? r.reasonPhrase ?? '') as String);
    }
    return body;
  }

  /// Register an issuer. Returns its id AND the bearer token (shown once) needed
  /// to authenticate provisioning.
  Future<({String issuerId, String token})> registerIssuer(String publicKeyHex,
      {Map<String, dynamic> policy = const {}}) async {
    final r = await _http.post(Uri.parse('$baseUrl/v1/issuers'),
        headers: _headers,
        body: jsonEncode({'public_key_hex': publicKeyHex, 'policy': policy}));
    final b = _parse(r);
    return (issuerId: b['issuer_id'] as String, token: b['token'] as String);
  }

  /// Revoke an issuer (an issuer may only revoke itself).
  Future<void> revokeIssuer(String issuerId) async {
    final r = await _http.post(
        Uri.parse('$baseUrl/v1/issuers/${Uri.encodeComponent(issuerId)}/revoke'),
        headers: _headers);
    _parse(r);
  }

  Future<Map<String, dynamic>> provision({
    required String uid,
    required String issuerId,
    required String bindingPayloadHex,
    required String signatureHex,
    int keyVersion = 1,
  }) async {
    final r = await _http.post(Uri.parse('$baseUrl/v1/tags/provision'),
        headers: _headers,
        body: jsonEncode({
          'uid': uid,
          'issuer_id': issuerId,
          'binding_payload_hex': bindingPayloadHex,
          'signature_hex': signatureHex,
          'key_version': keyVersion,
        }));
    return _parse(r);
  }

  /// Verify a scan. Returns the three independent booleans from the core.
  Future<VerifyResult> verify(String uid, int ctr, String cmacHex,
      {int keyVersion = 1}) async {
    final uri = Uri.parse('$baseUrl/v1/verify').replace(queryParameters: {
      'u': uid,
      'c': '$ctr',
      'm': cmacHex,
      'kv': '$keyVersion',
    });
    final r = await _http.get(uri, headers: _headers);
    return VerifyResult.fromJson(_parse(r));
  }
}

class VerifyResult {
  VerifyResult({
    required this.chipAuthentic,
    required this.notReplayed,
    required this.issuerVerified,
    this.issuerId,
    this.reason = '',
  });

  final bool chipAuthentic;
  final bool notReplayed;
  final bool issuerVerified;
  final String? issuerId;
  final String reason;

  bool get fullyValid => chipAuthentic && notReplayed && issuerVerified;

  factory VerifyResult.fromJson(Map<String, dynamic> j) => VerifyResult(
        chipAuthentic: j['chip_authentic'] as bool,
        notReplayed: j['not_replayed'] as bool,
        issuerVerified: j['issuer_verified'] as bool,
        issuerId: j['issuer_id'] as String?,
        reason: (j['reason'] ?? '') as String,
      );
}
