/** A Vault token, or a function returning a current one (for renewing tokens). */
export type VaultToken = string | (() => string | Promise<string>);

/**
 * Options for {@link VaultTransitSigner.create}.
 */
export interface VaultTransitSignerOptions {
    /** Vault address, for example `https://vault.example.com:8200`. */
    address: string;
    /** Token with `read` on `<mount>/keys/<name>` and `update` on `<mount>/sign/<name>`. */
    token: VaultToken;
    /** Name of the transit key. */
    keyName: string;
    /** Mount path of the transit secrets engine. Defaults to `transit`. */
    mountPath?: string;
    /**
     * Key version to sign with. Defaults to the latest version at creation
     * time, which is then pinned so a later rotation does not change the
     * signing key silently.
     */
    keyVersion?: number;
    /** Vault Enterprise namespace, sent as `X-Vault-Namespace`. */
    namespace?: string;
    /**
     * `fetch` implementation to use, for example one configured with a custom
     * TLS agent. Defaults to the global `fetch`.
     */
    fetch?: typeof fetch;
    /**
     * Verify every signature locally against the public key before returning
     * it. Defaults to `true`.
     */
    verifySignatures?: boolean;
}
