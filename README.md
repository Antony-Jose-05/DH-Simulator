# Diffie-Hellman Key Exchange Simulator
### FastAPI + HTML/JS

---

## Project Structure

```
dh_app/
├── main.py           ← FastAPI app (all crypto logic)
├── requirements.txt  ← Python dependencies
└── index.html        ← Interactive simulator UI
```

---

## How to Run

### Step 1 — Create and activate a virtual environment

**Mac / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows:**
```bat
python -m venv .venv
.venv\Scripts\activate
```

---

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

---

### Step 3 — Start the backend

```bash
uvicorn main:app --reload
```

Backend will be live at: http://localhost:8000

Auto-generated API docs available at: http://localhost:8000/docs

---

### Step 4 — Open the frontend

Open `index.html` in your browser. No build step needed.

---

### Next time you run it

You only need steps 3 and 4 — the venv and dependencies are already set up:

**Mac / Linux:**
```bash
source .venv/bin/activate
uvicorn main:app --reload
```

**Windows:**
```bat
.venv\Scripts\activate
uvicorn main:app --reload
```

---

## API Endpoints

| Method | Endpoint                          | Description                        |
|--------|-----------------------------------|------------------------------------|
| POST   | `/api/dh/exchange`                | Part 1: Basic DH key exchange      |
| POST   | `/api/mitm/attack`                | Part 2: Simulate MITM attack       |
| POST   | `/api/signatures/secure-exchange` | Part 3: DH secured with signatures |
| GET    | `/api/random-private?p=23`        | Generate a random valid private key|
| GET    | `/`                               | Health check                       |

---

## What Each Part Demonstrates

**Part 1 — Basic DH Exchange**
Alice and Bob agree on public parameters (p, g), each picks a private key,
computes a public key (g^private mod p), exchanges them, and independently
derives the same shared secret.

**Part 2 — MITM Attack**
Eve intercepts the channel, generates two fake key pairs, and substitutes
her public keys for Alice's and Bob's. She ends up with separate shared secrets
with each party and can decrypt all traffic.

**Part 3 — Digital Signature Defence**
Alice and Bob sign their DH public keys using RSA private keys before sending.
The receiver verifies the signature before using the key. Eve cannot forge
a valid signature without the RSA private key — MITM is blocked.