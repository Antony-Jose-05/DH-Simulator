from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import random

app = FastAPI(title="DH Key Exchange API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── DH Parameters ───────────────────────────────────────────
P = 23  # Prime modulus (use 2048-bit in production)
G = 5   # Generator / primitive root


# ─── Core DH Math ────────────────────────────────────────────
def dh_private_key() -> int:
    return random.randint(2, P - 2)

def dh_public_key(private: int) -> int:
    return pow(G, private, P)

def dh_shared_secret(their_public: int, my_private: int) -> int:
    return pow(their_public, my_private, P)


# ─── Tiny RSA (educational) ──────────────────────────────────
def mod_inverse(a: int, m: int) -> int:
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return (old_s % m + m) % m

def rsa_keypair(p: int, q: int):
    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = 17
    d   = mod_inverse(e, phi)
    return {"pub": [e, n], "priv": [d, n]}

def rsa_sign(msg: int, priv: list) -> int:
    d, n = priv
    return pow(msg % n, d, n)

def rsa_verify(msg: int, sig: int, pub: list) -> bool:
    e, n = pub
    return pow(sig, e, n) == (msg % n)

def simple_hash(val: int) -> int:
    h = 0
    for ch in str(val):
        h = (h * 31 + ord(ch)) % 3000
    return h


# ═════════════════════════════════════════════════════════════
#  ROUTES
# ═════════════════════════════════════════════════════════════

# ── Part 1: Basic DH ─────────────────────────────────────────
@app.get("/api/dh/exchange")
def dh_exchange():
    alice_priv  = dh_private_key()
    alice_pub   = dh_public_key(alice_priv)
    bob_priv    = dh_private_key()
    bob_pub     = dh_public_key(bob_priv)

    alice_secret = dh_shared_secret(bob_pub,   alice_priv)
    bob_secret   = dh_shared_secret(alice_pub, bob_priv)

    return {
        "params": {"p": P, "g": G},
        "alice": {
            "private_key": alice_priv,
            "public_key":  alice_pub,
            "formula":     f"{G}^{alice_priv} mod {P} = {alice_pub}",
            "shared_secret": alice_secret,
            "secret_formula": f"{bob_pub}^{alice_priv} mod {P} = {alice_secret}",
        },
        "bob": {
            "private_key": bob_priv,
            "public_key":  bob_pub,
            "formula":     f"{G}^{bob_priv} mod {P} = {bob_pub}",
            "shared_secret": bob_secret,
            "secret_formula": f"{alice_pub}^{bob_priv} mod {P} = {bob_secret}",
        },
        "match": alice_secret == bob_secret,
        "shared_secret": alice_secret,
    }


# ── Part 2: MITM Attack ───────────────────────────────────────
@app.get("/api/mitm/attack")
def mitm_attack():
    # Real key pairs
    alice_priv = dh_private_key()
    alice_pub  = dh_public_key(alice_priv)
    bob_priv   = dh_private_key()
    bob_pub    = dh_public_key(bob_priv)

    # Eve's two key pairs
    e_priv_a = dh_private_key()   # Eve ↔ Alice side
    e_pub_a  = dh_public_key(e_priv_a)
    e_priv_b = dh_private_key()   # Eve ↔ Bob side
    e_pub_b  = dh_public_key(e_priv_b)

    # Alice thinks she talks to Bob but talks to Eve
    alice_secret = dh_shared_secret(e_pub_b, alice_priv)
    # Bob thinks he talks to Alice but talks to Eve
    bob_secret   = dh_shared_secret(e_pub_a, bob_priv)

    # Eve's two shared secrets
    eve_with_alice = dh_shared_secret(alice_pub, e_priv_b)
    eve_with_bob   = dh_shared_secret(bob_pub,   e_priv_a)

    return {
        "alice": {
            "private_key": alice_priv,
            "public_key":  alice_pub,
            "thinks_shared_secret_with_bob": alice_secret,
        },
        "bob": {
            "private_key": bob_priv,
            "public_key":  bob_pub,
            "thinks_shared_secret_with_alice": bob_secret,
        },
        "eve": {
            "fake_pub_sent_to_bob":   e_pub_b,
            "fake_pub_sent_to_alice": e_pub_a,
            "secret_with_alice":      eve_with_alice,
            "secret_with_bob":        eve_with_bob,
        },
        "mitm_success": (
            alice_secret == eve_with_alice and
            bob_secret   == eve_with_bob
        ),
        "alice_compromised": alice_secret == eve_with_alice,
        "bob_compromised":   bob_secret   == eve_with_bob,
    }


# ── Part 3: Secure DH with Digital Signatures ────────────────
@app.get("/api/signatures/secure-exchange")
def secure_exchange():
    # RSA identity key pairs
    alice_rsa = rsa_keypair(61, 53)
    bob_rsa   = rsa_keypair(67, 71)

    # DH keys
    alice_priv = dh_private_key()
    alice_pub  = dh_public_key(alice_priv)
    bob_priv   = dh_private_key()
    bob_pub    = dh_public_key(bob_priv)

    # Sign DH public keys
    alice_hash = simple_hash(alice_pub)
    alice_sig  = rsa_sign(alice_hash, alice_rsa["priv"])
    bob_hash   = simple_hash(bob_pub)
    bob_sig    = rsa_sign(bob_hash,   bob_rsa["priv"])

    # Verify signatures
    alice_sig_valid = rsa_verify(simple_hash(alice_pub), alice_sig, alice_rsa["pub"])
    bob_sig_valid   = rsa_verify(simple_hash(bob_pub),   bob_sig,   bob_rsa["pub"])

    # Eve tries MITM with forged signature
    e_priv   = dh_private_key()
    e_pub    = dh_public_key(e_priv)
    forge_sig      = rsa_sign(simple_hash(e_pub), alice_rsa["priv"]) + 1  # tampered
    forge_detected = not rsa_verify(simple_hash(e_pub), forge_sig, alice_rsa["pub"])

    # Shared secret (only if both valid)
    alice_secret = dh_shared_secret(bob_pub,   alice_priv) if (alice_sig_valid and bob_sig_valid) else None
    bob_secret   = dh_shared_secret(alice_pub, bob_priv)   if (alice_sig_valid and bob_sig_valid) else None

    return {
        "alice": {
            "dh_public_key":  alice_pub,
            "rsa_public_key": alice_rsa["pub"],
            "dh_hash":        alice_hash,
            "signature":      alice_sig,
            "shared_secret":  alice_secret,
        },
        "bob": {
            "dh_public_key":  bob_pub,
            "rsa_public_key": bob_rsa["pub"],
            "dh_hash":        bob_hash,
            "signature":      bob_sig,
            "shared_secret":  bob_secret,
        },
        "verification": {
            "alice_sig_valid": alice_sig_valid,
            "bob_sig_valid":   bob_sig_valid,
            "both_verified":   alice_sig_valid and bob_sig_valid,
        },
        "eve_attempt": {
            "fake_pub":   e_pub,
            "forged_sig": forge_sig,
            "detected":   forge_detected,
        },
        "secure": alice_sig_valid and bob_sig_valid and alice_secret == bob_secret,
        "shared_secret": alice_secret,
    }


# ── Health check ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "DH Simulator API running", "version": "1.0"}