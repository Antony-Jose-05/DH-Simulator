"""
run.py — One-click launcher for the DH Key Exchange Simulator
Run from the same folder as main.py and index.html:  python run.py
"""

import subprocess
import sys
import time
import webbrowser
import urllib.request
from pathlib import Path

# ── Paths (everything is in the same flat folder) ─────────────────────
BASE         = Path(__file__).parent
MAIN_PY      = BASE / "main.py"
FRONTEND     = BASE / "index.html"
REQ_FILE     = BASE / "requirements.txt"
API_URL      = "http://localhost:8000"
FRONTEND_URL = FRONTEND.resolve().as_uri()

# ── Helpers ───────────────────────────────────────────────────────────
def log(msg, symbol="•"):   print(f"  {symbol}  {msg}")
def success(msg): log(msg, "OK ")
def info(msg):    log(msg, "-->")
def error(msg):   log(msg, "ERR")

def wait_for_api(timeout=20):
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

    # ── 1. Check Python version ───────────────────────────────────────
    info("Checking Python version...")
    if sys.version_info < (3, 8):
        error(f"Python 3.8+ required. You have {sys.version}")
        sys.exit(1)
    success(f"Python {sys.version.split()[0]} ok")

    # ── 2. Check required files exist ─────────────────────────────────
    info("Checking required files...")
    missing = [f for f in [MAIN_PY, FRONTEND, REQ_FILE] if not f.exists()]
    if missing:
        for f in missing:
            error(f"Missing file: {f.name}")
        sys.exit(1)
    success("All files found (main.py, index.html, requirements.txt)")

    # ── 3. Install dependencies ───────────────────────────────────────
    info("Installing dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQ_FILE), "-q"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        error("pip install failed:")
        print(result.stderr)
        sys.exit(1)
    success("fastapi + uvicorn installed")

    # ── 4. Start FastAPI backend ──────────────────────────────────────
    info("Starting FastAPI on http://localhost:8000 ...")

    # On Windows, prevent a second console window from popping up
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "0.0.0.0", "--port", "8000"],
        cwd=str(BASE),          # run from same folder as main.py
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs
    )

    # ── 5. Wait for API ───────────────────────────────────────────────
    info("Waiting for API to be ready...")
    if wait_for_api():
        success("API is up")
    else:
        error("API did not start in time.")
        error("Try manually: python -m uvicorn main:app --reload")
        server.terminate()
        sys.exit(1)

    # ── 6. Open browser ───────────────────────────────────────────────
    info("Opening frontend in browser...")
    webbrowser.open(FRONTEND_URL)
    success("Browser opened")

    # ── 7. Summary ────────────────────────────────────────────────────
    print()
    print("  ┌──────────────────────────────────────────────┐")
    print(f"  │  API        {API_URL:<34}│")
    print(f"  │  API Docs   {API_URL + '/docs':<34}│")
    print(f"  │  Frontend   {str(FRONTEND.name):<34}│")
    print("  └──────────────────────────────────────────────┘")
    print()
    print("  Press Ctrl+C to stop.\n")

    # ── 8. Keep alive until Ctrl+C ────────────────────────────────────
    try:
        server.wait()
    except KeyboardInterrupt:
        print()
        info("Shutting down...")
        server.terminate()
        server.wait()
        success("Server stopped. Goodbye!")
        print()

if __name__ == "__main__":
    main()