from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import random
from sympy import isprime, primitive_root

app = FastAPI(title="DH Key Exchange API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Core DH Math ────────────────────────────────────────────
def dh_public_key(g: int, private: int, p: int) -> int:
    return pow(g, private, p)

def dh_shared_secret(their_public: int, my_private: int, p: int) -> int:
    return pow(their_public, my_private, p)

def rand_private(p: int) -> int:
    return random.randint(2, p - 2)


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


# ─── Validation helper ────────────────────────────────────────
def validate_params(p: int, g: int):
    if not isprime(p):
        raise HTTPException(status_code=400, detail=f"p={p} is not a prime number.")
    if p < 5:
        raise HTTPException(status_code=400, detail="p must be at least 5.")
    if g < 2 or g >= p:
        raise HTTPException(status_code=400, detail=f"g must be between 2 and p-1.")

def validate_private(key: int, p: int, name: str):
    if key < 2 or key > p - 2:
        raise HTTPException(status_code=400, detail=f"{name} private key must be between 2 and {p-2}.")


# ═════════════════════════════════════════════════════════════
#  REQUEST MODELS
# ═════════════════════════════════════════════════════════════

class DHRequest(BaseModel):
    p: int = 23
    g: int = 5
    alice_private: Optional[int] = None
    bob_private:   Optional[int] = None

class MITMRequest(BaseModel):
    p: int = 23
    g: int = 5
    alice_private: Optional[int] = None
    bob_private:   Optional[int] = None
    eve_private_a: Optional[int] = None   # Eve ↔ Alice side
    eve_private_b: Optional[int] = None   # Eve ↔ Bob side

class SigRequest(BaseModel):
    p: int = 23
    g: int = 5
    alice_private: Optional[int] = None
    bob_private:   Optional[int] = None
    eve_private:   Optional[int] = None


# ═════════════════════════════════════════════════════════════
#  ROUTES
# ═════════════════════════════════════════════════════════════

# ── Part 1: Basic DH ─────────────────────────────────────────
@app.post("/api/dh/exchange")
def dh_exchange(req: DHRequest):
    validate_params(req.p, req.g)

    alice_priv = req.alice_private if req.alice_private is not None else rand_private(req.p)
    bob_priv   = req.bob_private   if req.bob_private   is not None else rand_private(req.p)

    validate_private(alice_priv, req.p, "Alice")
    validate_private(bob_priv,   req.p, "Bob")

    alice_pub    = dh_public_key(req.g, alice_priv, req.p)
    bob_pub      = dh_public_key(req.g, bob_priv,   req.p)
    alice_secret = dh_shared_secret(bob_pub,   alice_priv, req.p)
    bob_secret   = dh_shared_secret(alice_pub, bob_priv,   req.p)

    return {
        "params": {"p": req.p, "g": req.g},
        "alice": {
            "private_key":    alice_priv,
            "public_key":     alice_pub,
            "formula":        f"{req.g}^{alice_priv} mod {req.p} = {alice_pub}",
            "shared_secret":  alice_secret,
            "secret_formula": f"{bob_pub}^{alice_priv} mod {req.p} = {alice_secret}",
        },
        "bob": {
            "private_key":    bob_priv,
            "public_key":     bob_pub,
            "formula":        f"{req.g}^{bob_priv} mod {req.p} = {bob_pub}",
            "shared_secret":  bob_secret,
            "secret_formula": f"{alice_pub}^{bob_priv} mod {req.p} = {bob_secret}",
        },
        "match":          alice_secret == bob_secret,
        "shared_secret":  alice_secret,
    }


# ── Part 2: MITM Attack ───────────────────────────────────────
@app.post("/api/mitm/attack")
def mitm_attack(req: MITMRequest):
    validate_params(req.p, req.g)

    alice_priv = req.alice_private if req.alice_private is not None else rand_private(req.p)
    bob_priv   = req.bob_private   if req.bob_private   is not None else rand_private(req.p)
    e_priv_a   = req.eve_private_a if req.eve_private_a is not None else rand_private(req.p)
    e_priv_b   = req.eve_private_b if req.eve_private_b is not None else rand_private(req.p)

    for val, name in [(alice_priv,"Alice"),(bob_priv,"Bob"),(e_priv_a,"Eve(A)"),(e_priv_b,"Eve(B)")]:
        validate_private(val, req.p, name)

    alice_pub = dh_public_key(req.g, alice_priv, req.p)
    bob_pub   = dh_public_key(req.g, bob_priv,   req.p)
    e_pub_a   = dh_public_key(req.g, e_priv_a,   req.p)
    e_pub_b   = dh_public_key(req.g, e_priv_b,   req.p)

    alice_secret   = dh_shared_secret(e_pub_b,   alice_priv, req.p)
    bob_secret     = dh_shared_secret(e_pub_a,   bob_priv,   req.p)
    eve_with_alice = dh_shared_secret(alice_pub, e_priv_b,   req.p)
    eve_with_bob   = dh_shared_secret(bob_pub,   e_priv_a,   req.p)

    return {
        "params": {"p": req.p, "g": req.g},
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
            "private_key_a":      e_priv_a,
            "private_key_b":      e_priv_b,
            "fake_pub_sent_to_bob":   e_pub_b,
            "fake_pub_sent_to_alice": e_pub_a,
            "secret_with_alice":      eve_with_alice,
            "secret_with_bob":        eve_with_bob,
        },
        "mitm_success":     alice_secret == eve_with_alice and bob_secret == eve_with_bob,
        "alice_compromised": alice_secret == eve_with_alice,
        "bob_compromised":   bob_secret   == eve_with_bob,
    }


# ── Part 3: Secure DH with Digital Signatures ────────────────
@app.post("/api/signatures/secure-exchange")
def secure_exchange(req: SigRequest):
    validate_params(req.p, req.g)

    alice_priv = req.alice_private if req.alice_private is not None else rand_private(req.p)
    bob_priv   = req.bob_private   if req.bob_private   is not None else rand_private(req.p)
    e_priv     = req.eve_private   if req.eve_private   is not None else rand_private(req.p)

    validate_private(alice_priv, req.p, "Alice")
    validate_private(bob_priv,   req.p, "Bob")
    validate_private(e_priv,     req.p, "Eve")

    alice_rsa = rsa_keypair(61, 53)
    bob_rsa   = rsa_keypair(67, 71)

    alice_pub = dh_public_key(req.g, alice_priv, req.p)
    bob_pub   = dh_public_key(req.g, bob_priv,   req.p)
    e_pub     = dh_public_key(req.g, e_priv,     req.p)

    alice_hash = simple_hash(alice_pub)
    alice_sig  = rsa_sign(alice_hash, alice_rsa["priv"])
    bob_hash   = simple_hash(bob_pub)
    bob_sig    = rsa_sign(bob_hash, bob_rsa["priv"])

    alice_sig_valid = rsa_verify(simple_hash(alice_pub), alice_sig, alice_rsa["pub"])
    bob_sig_valid   = rsa_verify(simple_hash(bob_pub),   bob_sig,   bob_rsa["pub"])

    forge_sig      = rsa_sign(simple_hash(e_pub), alice_rsa["priv"]) + 1
    forge_detected = not rsa_verify(simple_hash(e_pub), forge_sig, alice_rsa["pub"])

    alice_secret = dh_shared_secret(bob_pub,   alice_priv, req.p) if (alice_sig_valid and bob_sig_valid) else None
    bob_secret   = dh_shared_secret(alice_pub, bob_priv,   req.p) if (alice_sig_valid and bob_sig_valid) else None

    return {
        "params": {"p": req.p, "g": req.g},
        "alice": {
            "private_key":    alice_priv,
            "dh_public_key":  alice_pub,
            "rsa_public_key": alice_rsa["pub"],
            "dh_hash":        alice_hash,
            "signature":      alice_sig,
            "shared_secret":  alice_secret,
        },
        "bob": {
            "private_key":    bob_priv,
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
            "private_key": e_priv,
            "fake_pub":    e_pub,
            "forged_sig":  forge_sig,
            "detected":    forge_detected,
        },
        "secure":        alice_sig_valid and bob_sig_valid and alice_secret == bob_secret,
        "shared_secret": alice_secret,
    }


# ── Utility: random valid private key ────────────────────────
@app.get("/api/random-private")
def random_private(p: int = 23):
    if not isprime(p) or p < 5:
        raise HTTPException(status_code=400, detail="Invalid prime.")
    return {"value": rand_private(p)}


# ── Health check ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "DH Simulator API running", "version": "2.0"}