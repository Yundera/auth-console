// In-browser Ed25519 SSH key generation.
//
// Generates a keypair with WebCrypto and hand-encodes it into the two formats
// OpenSSH expects: the single-line `ssh-ed25519 AAAA... comment` public key,
// and the `-----BEGIN OPENSSH PRIVATE KEY-----` (openssh-key-v1) private key.
// The private key never leaves the browser — only the public key is sent to
// the server to be appended to authorized_keys.

const ENC = new TextEncoder();
const ED25519_NAME = ENC.encode('ssh-ed25519');

function u32(n: number): Uint8Array {
    return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function concat(parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
}

// SSH wire "string": uint32 big-endian length prefix followed by the bytes.
function sshString(data: Uint8Array): Uint8Array {
    return concat([u32(data.length), data]);
}

function b64(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

// The public-key blob shared by the public key line, the private key file, and
// the fingerprint: string("ssh-ed25519") || string(pub32).
function publicKeyBlob(pub: Uint8Array): Uint8Array {
    return concat([sshString(ED25519_NAME), sshString(pub)]);
}

export function formatOpenSshPublicKey(pub: Uint8Array, comment: string): string {
    return `ssh-ed25519 ${b64(publicKeyBlob(pub))} ${comment}`.trim();
}

export function formatOpenSshPrivateKey(seed: Uint8Array, pub: Uint8Array, comment: string): string {
    const blob = publicKeyBlob(pub);

    // checkint appears twice; on decrypt OpenSSH verifies the two copies match.
    const checkint = new Uint8Array(4);
    crypto.getRandomValues(checkint);

    const priv = concat([seed, pub]); // ed25519 private = seed32 || pub32

    let privSection = concat([
        checkint, checkint,
        sshString(ED25519_NAME),
        sshString(pub),
        sshString(priv),
        sshString(ENC.encode(comment)),
    ]);

    // Pad with 1,2,3,... up to the "none" cipher block size (8).
    const padLen = (8 - (privSection.length % 8)) % 8;
    if (padLen > 0) {
        const pad = new Uint8Array(padLen);
        for (let i = 0; i < padLen; i++) pad[i] = i + 1;
        privSection = concat([privSection, pad]);
    }

    const body = concat([
        ENC.encode('openssh-key-v1\0'),
        sshString(ENC.encode('none')), // ciphername
        sshString(ENC.encode('none')), // kdfname
        sshString(new Uint8Array(0)),  // kdfoptions
        u32(1),                        // number of keys
        sshString(blob),               // public key
        sshString(privSection),        // private key section
    ]);

    const wrapped = (b64(body).match(/.{1,70}/g) || []).join('\n');
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

async function sha256Fingerprint(blob: Uint8Array): Promise<string> {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', blob as Uint8Array<ArrayBuffer>));
    return `SHA256:${b64(hash).replace(/=+$/, '')}`;
}

export interface GeneratedKey {
    publicKey: string;
    privateKey: string;
    fingerprint: string;
}

export async function generateEd25519Key(comment: string): Promise<GeneratedKey> {
    const kp = await crypto.subtle.generateKey(
        { name: 'Ed25519' } as unknown as Algorithm,
        true,
        ['sign', 'verify'],
    ) as CryptoKeyPair;
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    // PKCS8 for ed25519 ends with the 32-byte seed wrapped in an OCTET STRING;
    // the last 32 bytes are the raw seed.
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const seed = pkcs8.slice(pkcs8.length - 32);

    return {
        publicKey: formatOpenSshPublicKey(pub, comment),
        privateKey: formatOpenSshPrivateKey(seed, pub, comment),
        fingerprint: await sha256Fingerprint(publicKeyBlob(pub)),
    };
}

export function isEd25519GenerationSupported(): boolean {
    return typeof crypto !== 'undefined'
        && !!crypto.subtle
        && typeof crypto.subtle.generateKey === 'function';
}
