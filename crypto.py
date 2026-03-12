"""
rsa_crypto.py - RSA Asymmetric Encryption Module

From-scratch RSA implementation with OAEP padding (PKCS#1 v2.2).
Uses Python built-ins for low-level math operations:
    - pow(base, exp, mod) for modular exponentiation and modular inverse
    - secrets for cryptographically secure random number generation
    - hashlib.sha256 for OAEP/MGF1 hash operations

Author:  Kori Prins
"""

import base64
import hashlib
import json
import math
import secrets
from dataclasses import dataclass
from typing import Optional


__all__ = [
    "RSAPublicKey",
    "RSAPrivateKey",
    "RSAKeyPair",
    "RSAEngine",
    "generate_keypair",
    "key_fingerprint",
]

# SHA-256 digest length in bytes (used throughout OAEP operations)
_HASH_LEN = 32


# ---------------------------------------------------------------------------
# Prime generation
# ---------------------------------------------------------------------------

def _miller_rabin(n: int, rounds: int = 40) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    With 40 rounds the probability of a composite passing is <= 4^(-40),
    which is negligible for cryptographic purposes.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Decompose n - 1 as 2^r * d where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2          # random witness in [2, n-2]
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False                           # composite

    return True                                    # probably prime


def _generate_prime(bit_length: int) -> int:
    """Generate a cryptographically random prime of exactly *bit_length* bits."""
    while True:
        candidate = secrets.randbits(bit_length)
        candidate |= (1 << (bit_length - 1)) | 1  # force MSB=1 and odd
        if _miller_rabin(candidate):
            return candidate


# ---------------------------------------------------------------------------
# OAEP padding (PKCS#1 v2.2, Section 7.1)
# ---------------------------------------------------------------------------

def _mgf1(seed: bytes, length: int) -> bytes:
    """
    MGF1 mask generation function using SHA-256.

    Produces a pseudorandom byte mask of the requested *length*
    by iteratively hashing the seed concatenated with a 4-byte counter.
    """
    mask = b""
    counter = 0
    while len(mask) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        mask += hashlib.sha256(seed + counter_bytes).digest()
        counter += 1
    return mask[:length]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def _oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """
    OAEP-encode a plaintext message.

    Parameters
    ----------
    message : bytes
        Plaintext to encode.
    k : int
        RSA key length in bytes (octet length of n).
    label : bytes
        Optional label bound into the encoding (default empty).

    Returns
    -------
    bytes
        Encoded message of length *k*.
    """
    max_msg_len = k - 2 * _HASH_LEN - 2
    if len(message) > max_msg_len:
        raise ValueError(
            f"Message too long for key size. "
            f"Maximum {max_msg_len} bytes, got {len(message)} bytes."
        )

    l_hash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * _HASH_LEN - 2)
    db = l_hash + ps + b"\x01" + message               # length: k - hLen - 1

    seed = secrets.token_bytes(_HASH_LEN)
    db_mask = _mgf1(seed, k - _HASH_LEN - 1)
    masked_db = _xor_bytes(db, db_mask)
    seed_mask = _mgf1(masked_db, _HASH_LEN)
    masked_seed = _xor_bytes(seed, seed_mask)

    return b"\x00" + masked_seed + masked_db


def _oaep_decode(encoded: bytes, k: int, label: bytes = b"") -> bytes:
    """
    OAEP-decode an encoded message.

    All error paths raise the same generic ValueError to avoid
    leaking information that could aid a Manger/Bleichenbacher-style
    chosen-ciphertext attack.
    """
    _err = "Decryption error"

    if len(encoded) != k or encoded[0] != 0x00:
        raise ValueError(_err)

    masked_seed = encoded[1 : 1 + _HASH_LEN]
    masked_db = encoded[1 + _HASH_LEN :]

    seed_mask = _mgf1(masked_db, _HASH_LEN)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = _mgf1(seed, k - _HASH_LEN - 1)
    db = _xor_bytes(masked_db, db_mask)

    l_hash = hashlib.sha256(label).digest()
    if db[:_HASH_LEN] != l_hash:
        raise ValueError(_err)

    # Walk past the zero-padding to find the 0x01 separator
    i = _HASH_LEN
    while i < len(db):
        if db[i] == 0x01:
            return db[i + 1 :]
        if db[i] != 0x00:
            raise ValueError(_err)
        i += 1

    raise ValueError(_err)


# ---------------------------------------------------------------------------
# Key data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RSAPublicKey:
    """RSA public key (n, e) with PEM serialization."""

    n: int
    e: int
    bit_length: int

    def to_pem(self) -> str:
        """Serialize to a PEM-formatted string."""
        payload = json.dumps({
            "n": hex(self.n),
            "e": self.e,
            "bit_length": self.bit_length,
        }).encode("utf-8")
        b64 = base64.encodebytes(payload).decode("ascii").strip()
        return (
            "-----BEGIN RSA PUBLIC KEY-----\n"
            f"{b64}\n"
            "-----END RSA PUBLIC KEY-----"
        )

    @classmethod
    def from_pem(cls, pem: str) -> "RSAPublicKey":
        """Deserialize from a PEM-formatted string."""
        lines = pem.strip().splitlines()
        if lines[0] != "-----BEGIN RSA PUBLIC KEY-----":
            raise ValueError("Invalid PEM header for public key")
        if lines[-1] != "-----END RSA PUBLIC KEY-----":
            raise ValueError("Invalid PEM footer for public key")

        b64_data = "".join(lines[1:-1])
        data = json.loads(base64.decodebytes(b64_data.encode("ascii")))
        return cls(
            n=int(data["n"], 16),
            e=data["e"],
            bit_length=data["bit_length"],
        )


@dataclass(frozen=True)
class RSAPrivateKey:
    """
    RSA private key with CRT (Chinese Remainder Theorem) components.

    Storing p, q, dp, dq, and q_inv enables CRT-optimized decryption,
    which is roughly 4x faster than naive pow(c, d, n).
    """

    n: int
    d: int
    bit_length: int
    p: int
    q: int
    dp: int          # d mod (p - 1)
    dq: int          # d mod (q - 1)
    q_inv: int       # q^(-1) mod p

    def to_pem(self) -> str:
        """Serialize to a PEM-formatted string."""
        payload = json.dumps({
            "n": hex(self.n),
            "d": hex(self.d),
            "bit_length": self.bit_length,
            "p": hex(self.p),
            "q": hex(self.q),
            "dp": hex(self.dp),
            "dq": hex(self.dq),
            "q_inv": hex(self.q_inv),
        }).encode("utf-8")
        b64 = base64.encodebytes(payload).decode("ascii").strip()
        return (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{b64}\n"
            "-----END RSA PRIVATE KEY-----"
        )

    @classmethod
    def from_pem(cls, pem: str) -> "RSAPrivateKey":
        """Deserialize from a PEM-formatted string."""
        lines = pem.strip().splitlines()
        if lines[0] != "-----BEGIN RSA PRIVATE KEY-----":
            raise ValueError("Invalid PEM header for private key")
        if lines[-1] != "-----END RSA PRIVATE KEY-----":
            raise ValueError("Invalid PEM footer for private key")

        b64_data = "".join(lines[1:-1])
        data = json.loads(base64.decodebytes(b64_data.encode("ascii")))
        return cls(
            n=int(data["n"], 16),
            d=int(data["d"], 16),
            bit_length=data["bit_length"],
            p=int(data["p"], 16),
            q=int(data["q"], 16),
            dp=int(data["dp"], 16),
            dq=int(data["dq"], 16),
            q_inv=int(data["q_inv"], 16),
        )


@dataclass(frozen=True)
class RSAKeyPair:
    """Container for a matched RSA public/private key pair."""

    public: RSAPublicKey
    private: RSAPrivateKey

    def save(self, public_path: str, private_path: str) -> None:
        """Write public and private keys to separate PEM files."""
        with open(public_path, "w", encoding="utf-8") as fh:
            fh.write(self.public.to_pem())
        with open(private_path, "w", encoding="utf-8") as fh:
            fh.write(self.private.to_pem())

    @classmethod
    def load(cls, public_path: str, private_path: str) -> "RSAKeyPair":
        """Load a key pair from PEM files."""
        with open(public_path, "r", encoding="utf-8") as fh:
            public = RSAPublicKey.from_pem(fh.read())
        with open(private_path, "r", encoding="utf-8") as fh:
            private = RSAPrivateKey.from_pem(fh.read())
        return cls(public=public, private=private)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair(bit_length: int = 4096) -> RSAKeyPair:
    """
    Generate an RSA key pair of the specified bit length.

    Parameters
    ----------
    bit_length : int
        Desired modulus size in bits.  Minimum 2048.

    Returns
    -------
    RSAKeyPair
        A freshly generated key pair ready for encryption/decryption.
    """
    if bit_length < 2048:
        raise ValueError("Key size must be at least 2048 bits for security")

    half = bit_length // 2

    p = _generate_prime(half)
    q = _generate_prime(half)
    while q == p:
        q = _generate_prime(half)

    n = p * q
    lambda_n = math.lcm(p - 1, q - 1)      # Carmichael's totient

    e = 65537                                # standard public exponent
    if math.gcd(e, lambda_n) != 1:
        raise RuntimeError(
            "Public exponent e is not coprime with lambda(n). "
            "This is astronomically unlikely -- please regenerate."
        )

    d = pow(e, -1, lambda_n)                 # private exponent

    # CRT pre-computations
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = pow(q, -1, p)

    public = RSAPublicKey(n=n, e=e, bit_length=bit_length)
    private = RSAPrivateKey(
        n=n, d=d, bit_length=bit_length,
        p=p, q=q, dp=dp, dq=dq, q_inv=q_inv,
    )

    return RSAKeyPair(public=public, private=private)


# ---------------------------------------------------------------------------
# Encryption engine
# ---------------------------------------------------------------------------

class RSAEngine:
    """Stateless RSA-OAEP encryption and decryption operations."""

    @staticmethod
    def encrypt(
        plaintext: bytes,
        public_key: RSAPublicKey,
        label: bytes = b"",
    ) -> bytes:
        """
        Encrypt a plaintext message with RSA-OAEP.

        Parameters
        ----------
        plaintext : bytes
            Message to encrypt (max length depends on key size).
        public_key : RSAPublicKey
            Recipient's public key.
        label : bytes
            Optional label bound to the ciphertext.

        Returns
        -------
        bytes
            Ciphertext of the same octet length as the modulus.
        """
        k = (public_key.bit_length + 7) // 8       # key length in bytes

        encoded = _oaep_encode(plaintext, k, label)
        plaintext_int = int.from_bytes(encoded, byteorder="big")
        ciphertext_int = pow(plaintext_int, public_key.e, public_key.n)

        return ciphertext_int.to_bytes(k, byteorder="big")

    @staticmethod
    def decrypt(
        ciphertext: bytes,
        private_key: RSAPrivateKey,
        label: bytes = b"",
    ) -> bytes:
        """
        Decrypt ciphertext with RSA-OAEP using CRT optimization.

        Parameters
        ----------
        ciphertext : bytes
            Encrypted message bytes.
        private_key : RSAPrivateKey
            Recipient's private key.
        label : bytes
            Must match the label used during encryption.

        Returns
        -------
        bytes
            Recovered plaintext.
        """
        k = (private_key.bit_length + 7) // 8

        if len(ciphertext) != k:
            raise ValueError("Decryption error")

        c = int.from_bytes(ciphertext, byteorder="big")
        if c >= private_key.n:
            raise ValueError("Decryption error")

        # CRT-optimized decryption (~4x faster than pow(c, d, n))
        m1 = pow(c, private_key.dp, private_key.p)
        m2 = pow(c, private_key.dq, private_key.q)
        h = (private_key.q_inv * (m1 - m2)) % private_key.p
        plaintext_int = m2 + h * private_key.q

        encoded = plaintext_int.to_bytes(k, byteorder="big")

        return _oaep_decode(encoded, k, label)

    @staticmethod
    def max_plaintext_length(key: RSAPublicKey) -> int:
        """Return the maximum plaintext size in bytes for the given key."""
        k = (key.bit_length + 7) // 8
        return k - 2 * _HASH_LEN - 2


# ---------------------------------------------------------------------------
# Key fingerprint
# ---------------------------------------------------------------------------

def key_fingerprint(public_key: RSAPublicKey) -> bytes:
    """
    Compute a 32-byte SHA-256 fingerprint of a public key.

    Useful as a compact identity for message headers.
    """
    key_bytes = (
        public_key.n.to_bytes((public_key.bit_length + 7) // 8, "big")
        + public_key.e.to_bytes(4, "big")
    )
    return hashlib.sha256(key_bytes).digest()


# ---------------------------------------------------------------------------
# Self-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import time

    print("rsa_crypto.py - Self Test")
    print("=" * 60)

    # --- Key generation ---
    print("\n[1] Generating 4096-bit RSA key pair ...")
    t0 = time.perf_counter()
    keypair = generate_keypair(4096)
    elapsed = time.perf_counter() - t0
    print(f"    Generated in {elapsed:.2f}s")
    print(f"    Modulus n is {keypair.public.n.bit_length()} bits")

    engine = RSAEngine()
    max_len = engine.max_plaintext_length(keypair.public)
    print(f"    Max plaintext length: {max_len} bytes")

    # --- Encrypt / Decrypt ---
    print("\n[2] RSA-OAEP encrypt/decrypt round-trip ...")
    original = b"Hello from the RSA crypto module!"
    t0 = time.perf_counter()
    ciphertext = engine.encrypt(original, keypair.public)
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    recovered = engine.decrypt(ciphertext, keypair.private)
    dec_time = time.perf_counter() - t0

    assert recovered == original, "ROUND-TRIP FAILED"
    print(f"    Plaintext:   {original}")
    print(f"    Ciphertext:  {ciphertext[:32].hex()}... ({len(ciphertext)} bytes)")
    print(f"    Recovered:   {recovered}")
    print(f"    Encrypt: {enc_time * 1000:.1f}ms  |  Decrypt: {dec_time * 1000:.1f}ms")

    # --- PEM serialization ---
    print("\n[3] PEM serialization round-trip ...")
    pub_pem = keypair.public.to_pem()
    priv_pem = keypair.private.to_pem()
    pub_restored = RSAPublicKey.from_pem(pub_pem)
    priv_restored = RSAPrivateKey.from_pem(priv_pem)
    ct2 = engine.encrypt(b"PEM test", pub_restored)
    pt2 = engine.decrypt(ct2, priv_restored)
    assert pt2 == b"PEM test", "PEM ROUND-TRIP FAILED"
    print("    PEM export/import verified")

    # --- File I/O ---
    print("\n[4] File save/load round-trip ...")
    keypair.save("/tmp/test_pub.pem", "/tmp/test_priv.pem")
    loaded = RSAKeyPair.load("/tmp/test_pub.pem", "/tmp/test_priv.pem")
    ct3 = engine.encrypt(b"File I/O test", loaded.public)
    pt3 = engine.decrypt(ct3, loaded.private)
    assert pt3 == b"File I/O test", "FILE I/O ROUND-TRIP FAILED"
    print("    File save/load verified")

    # --- Max-length plaintext ---
    print("\n[5] Max-length plaintext test ...")
    max_msg = secrets.token_bytes(max_len)
    ct4 = engine.encrypt(max_msg, keypair.public)
    pt4 = engine.decrypt(ct4, keypair.private)
    assert pt4 == max_msg, "MAX-LENGTH ROUND-TRIP FAILED"
    print(f"    {max_len}-byte plaintext encrypted and recovered")

    # --- Key fingerprint ---
    print("\n[6] Key fingerprint ...")
    fp = key_fingerprint(keypair.public)
    fp2 = key_fingerprint(keypair.public)
    assert fp == fp2, "FINGERPRINT NOT DETERMINISTIC"
    assert len(fp) == 32, "FINGERPRINT LENGTH WRONG"
    print(f"    Fingerprint: {fp.hex()}")
    print("    Deterministic: verified")

    print("\n" + "=" * 60)
    print("All tests passed.")