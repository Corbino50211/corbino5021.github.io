"""Serves the E-Bike Simulator WebGL build and stores player accounts.

Run:  python server.py [port]
Port comes from the command line, then the PORT / SERVER_PORT env vars, else 8080.
Put this file next to index.html. Accounts are kept in data/accounts.json (never served).

API (JSON POST, same origin as the game):
  /api/login  {name, pin, mode, cash, ...}    -> mode "signup": creates the account (seeded with the sent save),
                                                  409 if the name is taken
                                               mode "login": checks the PIN, 404 if there's no such account
                                               no mode (old clients): creates if new, else checks the PIN
  /api/load   {name, token}                  -> the account's save
  /api/save   {name, token, cash, owned, ride, skins, skin, xp, day, streak}
                                               -> {cash, forced: true} once after an admin changed their cash
  /api/admin  {name, token, action: "list"}  -> [{name, cash}] of every account
              {name, token, action: "set", target, cash}
Admins are the account names listed in data/admins.txt (one per line, re-read on every request).
"""

import hashlib
import hmac
import json
import os
import posixpath
import secrets
import sys
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "accounts.json")
ADMINS_PATH = os.path.join(DATA_DIR, "admins.txt")
MAX_BODY = 2048
MAX_FAILS, LOCK_SECONDS = 5, 60
MAX_CASH = 2_000_000_000

lock = threading.Lock()
fails = {}  # name -> (count, locked_until)


def load_db():
    try:
        with open(DB_PATH, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_db(db):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f)
    os.replace(tmp, DB_PATH)  # atomic: a crash mid-write never corrupts the file


db = load_db()


def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 100_000).hex()


def clean_save(body):
    """Clamp client-sent numbers to sane ranges."""
    def num(key, lo, hi, default):
        v = body.get(key, default)
        return min(max(v, lo), hi) if isinstance(v, int) and not isinstance(v, bool) else default
    return {
        "cash": num("cash", 0, MAX_CASH, 0),
        "owned": num("owned", 0, 2**31 - 1, 1) | 1,
        "ride": num("ride", 0, 31, 0),
        "skins": num("skins", 0, 2**62, 1) | 1,  # 64-bit skin mask
        "skin": num("skin", 0, 63, 0),
        "xp": num("xp", 0, MAX_CASH, 0),
        "day": num("day", 0, 10**6, 0),        # UTC day of the last daily reward claim
        "streak": num("streak", 0, 10**4, 0),
    }


def public(acct):
    return {"name": acct["name"], "token": acct["token"], "cash": acct["cash"],
            "owned": acct["owned"], "ride": acct["ride"],
            # .get: accounts made before these fields existed
            "skins": acct.get("skins", 1), "skin": acct.get("skin", 0),
            "xp": acct.get("xp", 0), "day": acct.get("day", 0), "streak": acct.get("streak", 0)}


def login(body):
    name = str(body.get("name", "")).strip()
    pin = str(body.get("pin", ""))
    if not 1 <= len(name) <= 16:
        return 400, {"error": "Name must be 1-16 characters"}
    if not (pin.isdigit() and 4 <= len(pin) <= 8):
        return 400, {"error": "PIN must be 4-8 digits"}
    key = name.lower()
    now = time.time()
    count, until = fails.get(key, (0, 0))
    if until > now:
        return 429, {"error": f"Too many wrong PINs. Try again in {int(until - now) + 1}s"}

    mode = body.get("mode")
    acct = db.get(key)
    if acct is not None and mode == "signup":
        return 409, {"error": "That name is taken. Pick another or log in."}
    if acct is None and mode == "login":
        return 404, {"error": "No account with that name. Sign up first."}
    if acct is None:
        salt = secrets.token_hex(16)
        acct = {"name": name, "salt": salt, "pin": hash_pin(pin, salt),
                "token": secrets.token_hex(16), **clean_save(body)}
        db[key] = acct
        save_db(db)
        return 200, public(acct)

    if not hmac.compare_digest(acct["pin"], hash_pin(pin, acct["salt"])):
        count += 1
        fails[key] = (0, now + LOCK_SECONDS) if count >= MAX_FAILS else (count, 0)
        return 403, {"error": "Wrong PIN"}
    fails.pop(key, None)
    acct.pop("forced", None)  # the client is about to adopt the server's cash anyway
    return 200, public(acct)


def authed(body):
    acct = db.get(str(body.get("name", "")).strip().lower())
    if acct and hmac.compare_digest(acct["token"], str(body.get("token", ""))):
        return acct
    return None


def load(body):
    acct = authed(body)
    if not acct:
        return 401, {"error": "Please log in again"}
    acct.pop("forced", None)
    return 200, public(acct)


def save(body):
    acct = authed(body)
    if not acct:
        return 401, {"error": "Please log in again"}
    new = clean_save(body)
    if acct.pop("forced", False):  # an admin set this player's cash: the server's number wins
        new["cash"] = acct["cash"]
        acct.update(new)
        save_db(db)
        return 200, {"ok": True, "forced": True, "cash": acct["cash"]}
    acct.update(new)
    save_db(db)
    return 200, {"ok": True}


def admins():
    try:
        with open(ADMINS_PATH, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    except FileNotFoundError:
        return set()


def admin(body):
    acct = authed(body)
    if not acct or acct["name"].lower() not in admins():
        return 403, {"error": "Not an admin"}
    if body.get("action") == "list":
        return 200, {"players": sorted(({"name": a["name"], "cash": a["cash"]} for a in db.values()),
                                       key=lambda p: p["name"].lower())}
    if body.get("action") == "set":
        target = db.get(str(body.get("target", "")).strip().lower())
        if not target:
            return 404, {"error": "No such player"}
        target["cash"] = clean_save(body)["cash"]
        target["forced"] = True
        save_db(db)
        return 200, {"ok": True, "cash": target["cash"]}
    return 400, {"error": "Bad action"}


ROUTES = {"/api/login": login, "/api/load": load, "/api/save": save, "/api/admin": admin}


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".wasm": "application/wasm",
        ".js": "application/javascript",
        ".data": "application/octet-stream",
        ".unityweb": "application/octet-stream",
    }

    def send_head(self):
        # Never hand out the account file or this script.
        path = "/" + posixpath.normpath(unquote(self.path.split("?", 1)[0].split("#", 1)[0])).lstrip("/").lower()
        if path.startswith("/data") or path.endswith(".py"):
            self.send_error(404)
            return None
        return super().send_head()

    def do_POST(self):
        route = ROUTES.get(self.path.split("?", 1)[0])
        if not route:
            return self.reply(404, {"error": "Not found"})
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= MAX_BODY:
            return self.reply(400, {"error": "Bad request"})
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self.reply(400, {"error": "Bad JSON"})
        with lock:
            code, payload = route(body)
        self.reply(code, payload)

    def reply(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main():
    port = int(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PORT") or os.environ.get("SERVER_PORT") or 8080)
    server = ThreadingHTTPServer(("0.0.0.0", port), partial(Handler, directory=ROOT))
    if not os.path.exists(ADMINS_PATH):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(ADMINS_PATH, "w", encoding="utf-8") as f:
            f.write("# Account names that can use the in-game dev menu (/dev in chat), one per line.\n")
    print(f"E-Bike Simulator on http://0.0.0.0:{port}  ({len(db)} accounts)")
    server.serve_forever()


if __name__ == "__main__":
    main()
