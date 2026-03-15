"""
run.py — One-click launcher for the DH Key Exchange Simulator
Run this from the dh_app/ folder:  python run.py
"""

import subprocess
import sys
import os
import time
import webbrowser
import urllib.request
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────
BASE      = Path(__file__).parent
BACKEND   = BASE / "backend"
FRONTEND  = BASE / "frontend" / "index.html"
REQ_FILE  = BACKEND / "requirements.txt"
API_URL   = "http://localhost:8000"
FRONTEND_URL = FRONTEND.resolve().as_uri()

# ── Helpers ───────────────────────────────────────────────────────────
def log(msg, symbol="•"):
    print(f"  {symbol}  {msg}")

def success(msg):  log(msg, "✅")
def info(msg):     log(msg, "➜")
def error(msg):    log(msg, "❌")
def warn(msg):     log(msg, "⚠️")

def wait_for_api(timeout=15):
    """Poll the API until it responds or timeout is reached."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            urllib.request.urlopen(API_URL, timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False

# ── Main ──────────────────────────────────────────────────────────────
def main():
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║   Diffie-Hellman Key Exchange Simulator  ║")
    print("  ╚══════════════════════════════════════════╝")
    print()

    # ── 1. Check Python version ────────────────────────────────────────
    info("Checking Python version...")
    if sys.version_info < (3, 8):
        error(f"Python 3.8+ required. You have {sys.version}")
        sys.exit(1)
    success(f"Python {sys.version.split()[0]} detected")

    # ── 2. Check frontend exists ───────────────────────────────────────
    if not FRONTEND.exists():
        error(f"Frontend not found at: {FRONTEND}")
        sys.exit(1)
    success("Frontend file found")

    # ── 3. Install dependencies ────────────────────────────────────────
    info("Installing backend dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQ_FILE), "-q"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        error("pip install failed:")
        print(result.stderr)
        sys.exit(1)
    success("Dependencies installed (fastapi, uvicorn)")

    # ── 4. Start FastAPI backend ───────────────────────────────────────
    info("Starting FastAPI backend on http://localhost:8000 ...")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=str(BACKEND),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # ── 5. Wait for API to be ready ────────────────────────────────────
    info("Waiting for API to be ready...")
    if wait_for_api():
        success("API is up and running")
    else:
        error("API did not start in time. Try running manually:")
        print("       cd backend && uvicorn main:app --reload")
        server.terminate()
        sys.exit(1)

    # ── 6. Open frontend in browser ────────────────────────────────────
    info(f"Opening frontend in your browser...")
    webbrowser.open(FRONTEND_URL)
    success("Browser launched")

    # ── 7. Summary ─────────────────────────────────────────────────────
    print()
    print("  ┌─────────────────────────────────────────────┐")
    print(f"  │  API:       {API_URL:<33}│")
    print(f"  │  API Docs:  {API_URL + '/docs':<33}│")
    print(f"  │  Frontend:  Browser should be open now     │")
    print("  └─────────────────────────────────────────────┘")
    print()
    print("  Press Ctrl+C to stop the server.\n")

    # ── 8. Keep running until Ctrl+C ──────────────────────────────────
    try:
        server.wait()
    except KeyboardInterrupt:
        print()
        info("Shutting down server...")
        server.terminate()
        server.wait()
        success("Server stopped. Goodbye!")
        print()

if __name__ == "__main__":
    main()
