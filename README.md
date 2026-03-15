# Diffie-Hellman Key Exchange Simulator
### FastAPI + HTML/JS

---

## Project Structure

```
dh_app/
├── backend/
│   ├── main.py           ← FastAPI app (all crypto logic)
│   └── requirements.txt  ← Python dependencies
├── frontend/
│   └── index.html        ← Interactive step-by-step UI
└── run.py                ← One-click launcher
```

---

## How to Run

### Option A — One-click launcher (recommended)

```bash
python run.py
```

This will automatically install dependencies, start the backend, and open the frontend in your browser.

### Option B — Manual

#### Step 1 — Start the backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend will be live at: http://localhost:8000

You can also explore the auto-generated API docs at:
http://localhost:8000/docs

#### Step 2 — Open the frontend

Just open `frontend/index.html` in your browser.
No build step, no server needed for the frontend.

---

## API Endpoints

| Method | Endpoint                          | Description                        |
|--------|-----------------------------------|------------------------------------|
| GET    | `/api/dh/exchange`                | Part 1: Basic DH key exchange      |
| GET    | `/api/mitm/attack`                | Part 2: Simulate MITM attack       |
| GET    | `/api/signatures/secure-exchange` | Part 3: DH secured with signatures |
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
