/** HTTP client for the AttestCore web API. Domain-agnostic. */

export interface VerifyResult {
  chip_authentic: boolean;
  not_replayed: boolean;
  issuer_verified: boolean;
  issuer_id?: string | null;
  reason: string;
}

export interface ProvisionResult {
  uid: string;
  chip_key_hex: string;
  key_version: number;
  binding_id: string;
}

/** Thrown on any non-2xx response, carrying the status and the API's detail. */
export class AttestApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`AttestCore ${status}: ${detail}`);
    this.name = "AttestApiError";
  }
}

export class AttestClient {
  constructor(
    private readonly baseUrl: string,
    private readonly bearerToken?: string,
  ) {}

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      ...(this.bearerToken ? { Authorization: `Bearer ${this.bearerToken}` } : {}),
    };
  }

  /** Parse a response, throwing AttestApiError on non-2xx instead of returning
   *  an error body cast as a success type. */
  private async parse<T>(r: Response): Promise<T> {
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      const detail = (body as { detail?: string }).detail ?? r.statusText;
      throw new AttestApiError(r.status, detail);
    }
    return body as T;
  }

  /** Register an issuer. Returns its id AND the bearer token (shown once) needed
   *  to authenticate provisioning. */
  async registerIssuer(
    publicKeyHex: string,
    policy: Record<string, unknown> = {},
  ): Promise<{ issuerId: string; token: string }> {
    const r = await fetch(`${this.baseUrl}/v1/issuers`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ public_key_hex: publicKeyHex, policy }),
    });
    const b = await this.parse<{ issuer_id: string; token: string }>(r);
    return { issuerId: b.issuer_id, token: b.token };
  }

  /** Revoke an issuer (an issuer may only revoke itself). */
  async revokeIssuer(issuerId: string): Promise<void> {
    const r = await fetch(`${this.baseUrl}/v1/issuers/${encodeURIComponent(issuerId)}/revoke`, {
      method: "POST",
      headers: this.headers(),
    });
    await this.parse<{ status: string }>(r);
  }

  async provision(args: {
    uid: string;
    issuerId: string;
    bindingPayloadHex: string;
    signatureHex: string;
    keyVersion?: number;
  }): Promise<ProvisionResult> {
    const r = await fetch(`${this.baseUrl}/v1/tags/provision`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        uid: args.uid,
        issuer_id: args.issuerId,
        binding_payload_hex: args.bindingPayloadHex,
        signature_hex: args.signatureHex,
        key_version: args.keyVersion ?? 1,
      }),
    });
    return this.parse<ProvisionResult>(r);
  }

  async verify(uid: string, ctr: number, cmacHex: string, keyVersion = 1): Promise<VerifyResult> {
    const qs = new URLSearchParams({ u: uid, c: String(ctr), m: cmacHex, kv: String(keyVersion) });
    const r = await fetch(`${this.baseUrl}/v1/verify?${qs}`, { headers: this.headers() });
    return this.parse<VerifyResult>(r);
  }
}

export const fullyValid = (v: VerifyResult): boolean =>
  v.chip_authentic && v.not_replayed && v.issuer_verified;
