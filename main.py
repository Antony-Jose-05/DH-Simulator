from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import random
from math import gcd
from sympy import isprime, primitive_root

app = FastAPI(title="DH + MITM + Signature Simulation")

# ============================================================
# REQUEST MODELS
# ============================================================

class DHRequest(BaseModel):
    p: int
    g: int
    alice_private: int = None
    bob_private: int = None


class MITMRequest(BaseModel):
    p: int
    g: int
    alice_private: int = None
    bob_private: int = None
    eve_private1: int = None
    eve_private2: int = None


class SecureDHRequest(BaseModel):
    p: int
    g: int
    alice_private: int = None
    bob_private: int = None


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def validate_params(p: int, g: int):
    """
    Validates Diffie-Hellman parameters.

    p must be prime
    g must be in range (2 <= g < p)

    (Optional improvement: check primitive root)
    """
    if not isprime(p):
        raise HTTPException(status_code=400, detail="p must be a prime number.")

    if not (2 <= g < p):
        raise HTTPException(status_code=400, detail="g must satisfy 2 <= g < p.")


def validate_private(key: int, p: int, name: str):
    """
    Validates private key range.

    Valid DH private key range:
        2 <= private <= p-2
    """
    if key < 2 or key > p - 2:
        raise HTTPException(
            status_code=400,
            detail=f"{name} private key must be between 2 and {p-2}."
        )


# ============================================================
# DIFFIE-HELLMAN FUNCTIONS
# ============================================================

def dh_public_key(g: int, private: int, p: int) -> int:
    """
    Computes DH public key:
        public = g^private mod p
    """
    return pow(g, private, p)


def dh_shared_secret(their_public: int, my_private: int, p: int) -> int:
    """
    Computes shared secret:
        secret = (their_public)^my_private mod p
    """
    return pow(their_public, my_private, p)


def rand_private(p: int) -> int:
    """Generates random private key."""
    return random.randint(2, p - 2)


# ============================================================
# SIMPLE HASH FUNCTION (EDUCATIONAL ONLY)
# ============================================================

def simple_hash(val: int) -> int:
    """
    Very basic hash function (NOT secure).

    Used only to demonstrate digital signatures.
    """
    return (val * 31 + 17) % 100000


# ============================================================
# RSA (EDUCATIONAL IMPLEMENTATION)
# ============================================================

def rsa_keypair(p: int, q: int):
    """
    Generates RSA key pair.

    NOTE: This is a SMALL and INSECURE implementation,
    used only for demonstration.
    """
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1:
        e += 2

    # Compute modular inverse (private key)
    d = pow(e, -1, phi)

    return (e, n), (d, n)


def rsa_sign(message: int, privkey):
    """
    Signs a message using RSA private key.
    """
    d, n = privkey
    return pow(message, d, n)


def rsa_verify(message: int, signature: int, pubkey):
    """
    Verifies RSA signature.
    """
    e, n = pubkey
    return pow(signature, e, n) == message


# ============================================================
# API 1: NORMAL DIFFIE-HELLMAN
# ============================================================

@app.post("/api/dh/compute")
def dh_compute(req: DHRequest):
    """
    Normal Diffie-Hellman key exchange.

    Steps:
    1. Generate private keys
    2. Compute public keys
    3. Exchange public keys
    4. Compute shared secret
    """

    p, g = req.p, req.g
    validate_params(p, g)

    alice_priv = req.alice_private or rand_private(p)
    bob_priv = req.bob_private or rand_private(p)

    validate_private(alice_priv, p, "Alice")
    validate_private(bob_priv, p, "Bob")

    # Generate public keys
    alice_pub = dh_public_key(g, alice_priv, p)
    bob_pub = dh_public_key(g, bob_priv, p)

    # Compute shared secrets
    alice_secret = dh_shared_secret(bob_pub, alice_priv, p)
    bob_secret = dh_shared_secret(alice_pub, bob_priv, p)

    return {
        "alice_public": alice_pub,
        "bob_public": bob_pub,
        "alice_secret": alice_secret,
        "bob_secret": bob_secret,
        "match": alice_secret == bob_secret
    }


# ============================================================
# API 2: MITM ATTACK SIMULATION
# ============================================================

@app.post("/api/mitm/attack")
def mitm_attack(req: MITMRequest):
    """
    Simulates Man-in-the-Middle attack.

    Eve intercepts and replaces public keys.

    Result:
        Alice ↔ Eve (secret 1)
        Bob   ↔ Eve (secret 2)
    """

    p, g = req.p, req.g
    validate_params(p, g)

    # Private keys
    alice_priv = req.alice_private or rand_private(p)
    bob_priv = req.bob_private or rand_private(p)
    eve_priv_a = req.eve_private1 or rand_private(p)
    eve_priv_b = req.eve_private2 or rand_private(p)

    validate_private(alice_priv, p, "Alice")
    validate_private(bob_priv, p, "Bob")

    # Public keys
    alice_pub = dh_public_key(g, alice_priv, p)
    bob_pub = dh_public_key(g, bob_priv, p)

    eve_pub_a = dh_public_key(g, eve_priv_a, p)
    eve_pub_b = dh_public_key(g, eve_priv_b, p)

    # Attack happens here
    alice_secret = dh_shared_secret(eve_pub_b, alice_priv, p)
    bob_secret = dh_shared_secret(eve_pub_a, bob_priv, p)

    eve_with_alice = dh_shared_secret(alice_pub, eve_priv_b, p)
    eve_with_bob = dh_shared_secret(bob_pub, eve_priv_a, p)

    return {
        "alice_secret": alice_secret,
        "bob_secret": bob_secret,
        "eve_with_alice": eve_with_alice,
        "eve_with_bob": eve_with_bob,
        "attack_success": (
            alice_secret == eve_with_alice and
            bob_secret == eve_with_bob
        )
    }


# ============================================================
# API 3: SECURE DH WITH DIGITAL SIGNATURES
# ============================================================

@app.post("/api/dh/secure")
def secure_dh(req: SecureDHRequest):
    """
    Prevent MITM using digital signatures.

    Steps:
    1. Generate DH public keys
    2. Hash them
    3. Sign using RSA
    4. Verify signatures before accepting keys
    """

    p, g = req.p, req.g
    validate_params(p, g)

    alice_priv = req.alice_private or rand_private(p)
    bob_priv = req.bob_private or rand_private(p)

    validate_private(alice_priv, p, "Alice")
    validate_private(bob_priv, p, "Bob")

    # DH public keys
    alice_pub = dh_public_key(g, alice_priv, p)
    bob_pub = dh_public_key(g, bob_priv, p)

    # Generate RSA keys (educational)
    alice_pubkey, alice_privkey = rsa_keypair(61, 53)
    bob_pubkey, bob_privkey = rsa_keypair(67, 71)

    # Hash public keys
    alice_hash = simple_hash(alice_pub)
    bob_hash = simple_hash(bob_pub)

    # Sign hashes
    alice_sig = rsa_sign(alice_hash, alice_privkey)
    bob_sig = rsa_sign(bob_hash, bob_privkey)

    # Verify signatures
    alice_valid = rsa_verify(alice_hash, alice_sig, alice_pubkey)
    bob_valid = rsa_verify(bob_hash, bob_sig, bob_pubkey)

    if not (alice_valid and bob_valid):
        return {"error": "MITM detected!"}

    # Compute shared secrets
    alice_secret = dh_shared_secret(bob_pub, alice_priv, p)
    bob_secret = dh_shared_secret(alice_pub, bob_priv, p)

    return {
        "alice_secret": alice_secret,
        "bob_secret": bob_secret,
        "secure": True
    }