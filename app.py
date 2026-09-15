"""EVE Abyssal Deadspace PvE tracker.

Watches wallet transactions and character location via ESI:
  - Enters an abyssal system -> opens a "run" row; leaving closes it with duration.
  - Wallet transactions are auto-classified as loot / filament / ammo / other.
  - Manual per-transaction override is supported from the UI.
  - Aggregate ISK/hr = (loot sales - filament buys - ammo buys) / total time in abyss.
"""
import base64
import json
import os
import secrets as _secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from flask import Flask, g, jsonify, redirect, render_template, request, session

from abyss_data import (
    ABYSS_REGION_IDS,
    DEFAULT_AMMO_NAMES,
    FILAMENT_NAMES,
    LOOT_NAME_CONTAINS,
    LOOT_NAME_SUFFIXES,
    TRIG_LOOT_NAMES,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
_CFG_FILE = os.path.join(HERE, "config.json")
DB_FILE = os.path.join(HERE, "tracker.db")


def _load_cfg():
    if os.path.exists(_CFG_FILE):
        with open(_CFG_FILE) as f:
            return json.load(f)
    return {}


def _save_cfg(cfg):
    with open(_CFG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


_cfg = _load_cfg()
CLIENT_ID = _cfg.get("eve_client_id", "")
CLIENT_SECRET = _cfg.get("eve_client_secret", "")
CALLBACK_URL = _cfg.get("callback_url", "http://10.0.0.33:5051/sso/callback")
EXTRA_AMMO_TYPE_IDS = set(_cfg.get("extra_ammo_type_ids") or [])

_flask_secret = _cfg.get("flask_secret")
if not _flask_secret:
    _flask_secret = _secrets.token_hex(32)
    _cfg["flask_secret"] = _flask_secret
    try:
        _save_cfg(_cfg)
    except Exception:
        pass

ESI_BASE = "https://esi.evetech.net/latest"
EVE_SSO_AUTH = "https://login.eveonline.com/v2/oauth/authorize"
EVE_SSO_TOKEN = "https://login.eveonline.com/v2/oauth/token"
EVE_SCOPE = " ".join([
    "esi-location.read_location.v1",
    "esi-wallet.read_character_wallet.v1",
])

LOCATION_POLL_S = 10
WALLET_POLL_S = 300
TYPE_LOOKUP_BATCH = 500

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = _flask_secret

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
_db_lock = threading.Lock()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def db_direct():
    """For background threads (no Flask app context)."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_direct()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            character_id INTEGER NOT NULL,
            character_name TEXT NOT NULL,
            access_token TEXT,
            refresh_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at INTEGER NOT NULL,
            ended_at INTEGER,
            system_id INTEGER,
            system_name TEXT,
            duration_s INTEGER
        );
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY,
            date INTEGER NOT NULL,
            type_id INTEGER NOT NULL,
            type_name TEXT,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            is_buy INTEGER NOT NULL,
            auto_category TEXT,
            manual_category TEXT
        );
        CREATE TABLE IF NOT EXISTS type_name_cache (
            type_id INTEGER PRIMARY KEY,
            type_name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        conn.commit()
    finally:
        conn.close()


def state_get(key, default=None):
    conn = db_direct()
    try:
        row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def state_set(key, value):
    conn = db_direct()
    try:
        conn.execute(
            "INSERT INTO state(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Token / SSO
# ---------------------------------------------------------------------------
def sso_basic_auth():
    return base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()


def store_tokens(character_id, character_name, access_token, refresh_token, expires_in):
    conn = db_direct()
    try:
        conn.execute("DELETE FROM tokens")
        conn.execute(
            "INSERT INTO tokens (id, character_id, character_name, access_token, "
            "refresh_token, expires_at) VALUES (1,?,?,?,?,?)",
            (character_id, character_name, access_token, refresh_token,
             int(time.time()) + int(expires_in) - 30),
        )
        conn.commit()
    finally:
        conn.close()


def get_stored_tokens():
    conn = db_direct()
    try:
        return conn.execute("SELECT * FROM tokens WHERE id=1").fetchone()
    finally:
        conn.close()


def refresh_access_token():
    row = get_stored_tokens()
    if not row:
        return None
    r = requests.post(
        EVE_SSO_TOKEN,
        headers={
            "Authorization": f"Basic {sso_basic_auth()}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "login.eveonline.com",
        },
        data={"grant_type": "refresh_token", "refresh_token": row["refresh_token"]},
        timeout=15,
    )
    if r.status_code != 200:
        app.logger.warning("refresh failed: %s %s", r.status_code, r.text[:200])
        return None
    tok = r.json()
    conn = db_direct()
    try:
        conn.execute(
            "UPDATE tokens SET access_token=?, refresh_token=?, expires_at=? WHERE id=1",
            (tok["access_token"], tok.get("refresh_token", row["refresh_token"]),
             int(time.time()) + int(tok["expires_in"]) - 30),
        )
        conn.commit()
    finally:
        conn.close()
    return tok["access_token"]


def get_valid_access_token():
    row = get_stored_tokens()
    if not row:
        return None, None
    if int(row["expires_at"]) <= int(time.time()):
        tok = refresh_access_token()
        return tok, row["character_id"]
    return row["access_token"], row["character_id"]


# ---------------------------------------------------------------------------
# ESI helpers
# ---------------------------------------------------------------------------
def esi_get(path, params=None, token=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(f"{ESI_BASE}{path}", params=params, headers=headers, timeout=20)
    return r


def resolve_names_to_ids(names):
    """POST /universe/ids/ -- returns dict of name -> id. Non-strict: unmatched names are dropped."""
    if not names:
        return {}
    out = {}
    for i in range(0, len(names), TYPE_LOOKUP_BATCH):
        chunk = list(names)[i:i + TYPE_LOOKUP_BATCH]
        r = requests.post(f"{ESI_BASE}/universe/ids/", json=chunk, timeout=20)
        if r.status_code != 200:
            app.logger.warning("universe/ids failed: %s", r.text[:200])
            continue
        data = r.json() or {}
        for item in data.get("inventory_types", []) or []:
            out[item["name"]] = item["id"]
    return out


def resolve_ids_to_names(ids):
    """POST /universe/names/ -- returns dict of id -> name."""
    if not ids:
        return {}
    out = {}
    ids = list({int(x) for x in ids})
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        r = requests.post(f"{ESI_BASE}/universe/names/", json=chunk, timeout=20)
        if r.status_code != 200:
            continue
        for item in r.json() or []:
            out[item["id"]] = item["name"]
    return out


# ---------------------------------------------------------------------------
# Classification sets (loaded at startup, cached in DB)
# ---------------------------------------------------------------------------
LOOT_TYPE_IDS = set()
FILAMENT_TYPE_IDS = set()
AMMO_TYPE_IDS = set()
ABYSS_SYSTEM_IDS = set()


def _cache_type_names(mapping):
    conn = db_direct()
    try:
        for tid, name in mapping.items():
            conn.execute(
                "INSERT OR REPLACE INTO type_name_cache(type_id, type_name) VALUES(?,?)",
                (tid, name),
            )
        conn.commit()
    finally:
        conn.close()


def load_classification_sets():
    global LOOT_TYPE_IDS, FILAMENT_TYPE_IDS, AMMO_TYPE_IDS
    all_names = list(set(TRIG_LOOT_NAMES + FILAMENT_NAMES + DEFAULT_AMMO_NAMES))
    name_to_id = resolve_names_to_ids(all_names)
    _cache_type_names({v: k for k, v in name_to_id.items()})

    LOOT_TYPE_IDS = {name_to_id[n] for n in TRIG_LOOT_NAMES if n in name_to_id}
    FILAMENT_TYPE_IDS = {name_to_id[n] for n in FILAMENT_NAMES if n in name_to_id}
    AMMO_TYPE_IDS = {name_to_id[n] for n in DEFAULT_AMMO_NAMES if n in name_to_id}
    AMMO_TYPE_IDS |= EXTRA_AMMO_TYPE_IDS
    app.logger.info(
        "classification: loot=%d filament=%d ammo=%d (resolved %d of %d names)",
        len(LOOT_TYPE_IDS), len(FILAMENT_TYPE_IDS), len(AMMO_TYPE_IDS),
        len(name_to_id), len(all_names),
    )


def load_abyss_systems():
    """Walk abyss regions -> constellations -> systems and cache the ID set."""
    global ABYSS_SYSTEM_IDS
    cached = state_get("abyss_system_ids")
    if cached:
        try:
            ABYSS_SYSTEM_IDS = {int(x) for x in json.loads(cached)}
            app.logger.info("abyss systems (cache): %d", len(ABYSS_SYSTEM_IDS))
            return
        except Exception:
            pass
    ids = set()
    for region_id in ABYSS_REGION_IDS:
        r = esi_get(f"/universe/regions/{region_id}/")
        if r.status_code != 200:
            continue
        for constellation_id in r.json().get("constellations", []) or []:
            rc = esi_get(f"/universe/constellations/{constellation_id}/")
            if rc.status_code != 200:
                continue
            for system_id in rc.json().get("systems", []) or []:
                ids.add(int(system_id))
    ABYSS_SYSTEM_IDS = ids
    state_set("abyss_system_ids", json.dumps(list(ids)))
    app.logger.info("abyss systems (fresh): %d", len(ABYSS_SYSTEM_IDS))


def classify(type_id, type_name=None):
    if type_id in LOOT_TYPE_IDS:
        return "loot"
    if type_id in FILAMENT_TYPE_IDS:
        return "filament"
    if type_id in AMMO_TYPE_IDS:
        return "ammo"
    if type_name:
        if any(type_name.endswith(s) for s in LOOT_NAME_SUFFIXES):
            return "loot"
        if any(s in type_name for s in LOOT_NAME_CONTAINS):
            return "loot"
    return "other"


# ---------------------------------------------------------------------------
# Poll threads
# ---------------------------------------------------------------------------
def poll_location_loop():
    while True:
        try:
            token, char_id = get_valid_access_token()
            if token and char_id:
                r = esi_get(f"/characters/{char_id}/location/", token=token)
                if r.status_code == 200:
                    system_id = int(r.json().get("solar_system_id", 0))
                    in_abyss = system_id in ABYSS_SYSTEM_IDS
                    _reconcile_run(system_id, in_abyss)
        except Exception as e:
            app.logger.warning("location poll error: %s", e)
        time.sleep(LOCATION_POLL_S)


def _reconcile_run(system_id, in_abyss):
    conn = db_direct()
    try:
        open_run = conn.execute(
            "SELECT * FROM runs WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        now = int(time.time())
        if in_abyss and not open_run:
            name = _system_name(system_id)
            conn.execute(
                "INSERT INTO runs(started_at, system_id, system_name) VALUES(?,?,?)",
                (now, system_id, name),
            )
            conn.commit()
        elif (not in_abyss) and open_run:
            duration = now - int(open_run["started_at"])
            conn.execute(
                "UPDATE runs SET ended_at=?, duration_s=? WHERE id=?",
                (now, duration, open_run["id"]),
            )
            conn.commit()
    finally:
        conn.close()


def _system_name(system_id):
    if not system_id:
        return None
    conn = db_direct()
    try:
        row = conn.execute(
            "SELECT type_name FROM type_name_cache WHERE type_id=?", (system_id,)
        ).fetchone()
        if row:
            return row["type_name"]
    finally:
        conn.close()
    r = esi_get(f"/universe/systems/{system_id}/")
    if r.status_code == 200:
        name = r.json().get("name")
        if name:
            _cache_type_names({system_id: name})
        return name
    return None


def poll_wallet_loop():
    while True:
        try:
            token, char_id = get_valid_access_token()
            if token and char_id:
                _fetch_and_store_transactions(char_id, token)
        except Exception as e:
            app.logger.warning("wallet poll error: %s", e)
        time.sleep(WALLET_POLL_S)


def _fetch_and_store_transactions(char_id, token):
    r = esi_get(f"/characters/{char_id}/wallet/transactions/", token=token)
    if r.status_code != 200:
        return
    rows = r.json() or []
    if not rows:
        return
    conn = db_direct()
    try:
        existing = {r["transaction_id"] for r in conn.execute(
            "SELECT transaction_id FROM transactions"
        ).fetchall()}
        new_rows = [row for row in rows if row["transaction_id"] not in existing]
        if not new_rows:
            return
        unknown_type_ids = list({int(row["type_id"]) for row in new_rows})
        cached_names = {r["type_id"]: r["type_name"] for r in conn.execute(
            f"SELECT type_id, type_name FROM type_name_cache WHERE type_id IN "
            f"({','.join('?' * len(unknown_type_ids))})", unknown_type_ids
        ).fetchall()} if unknown_type_ids else {}
        need_resolve = [tid for tid in unknown_type_ids if tid not in cached_names]
        if need_resolve:
            resolved = resolve_ids_to_names(need_resolve)
            _cache_type_names(resolved)
            cached_names.update(resolved)
        for row in new_rows:
            type_id = int(row["type_id"])
            ts = int(datetime.strptime(row["date"], "%Y-%m-%dT%H:%M:%SZ")
                     .replace(tzinfo=timezone.utc).timestamp())
            type_name = cached_names.get(type_id)
            conn.execute(
                "INSERT OR IGNORE INTO transactions(transaction_id, date, type_id, "
                "type_name, quantity, unit_price, is_buy, auto_category) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    int(row["transaction_id"]), ts, type_id, type_name,
                    int(row["quantity"]), float(row["unit_price"]),
                    1 if row.get("is_buy") else 0,
                    classify(type_id, type_name),
                ),
            )
        conn.commit()
        app.logger.info("stored %d new transactions", len(new_rows))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
def _effective_category_sql():
    return "COALESCE(NULLIF(manual_category,''), auto_category)"


def compute_stats(since_ts=None):
    conn = db_direct()
    try:
        cat_expr = _effective_category_sql()
        where = ""
        params = []
        if since_ts:
            where = " WHERE date >= ?"
            params.append(since_ts)

        agg = conn.execute(
            f"SELECT {cat_expr} AS cat, is_buy, SUM(quantity*unit_price) AS gross, "
            f"COUNT(*) AS n FROM transactions{where} GROUP BY cat, is_buy",
            params,
        ).fetchall()

        loot_rev = filament_cost = ammo_cost = expense_cost = 0.0
        for row in agg:
            cat = row["cat"] or "other"
            is_buy = bool(row["is_buy"])
            gross = float(row["gross"] or 0.0)
            if cat == "loot" and not is_buy:
                loot_rev += gross
            elif cat == "filament" and is_buy:
                filament_cost += gross
            elif cat == "ammo" and is_buy:
                ammo_cost += gross
            elif cat == "expense" and is_buy:
                expense_cost += gross

        runs_where = "" if not since_ts else " WHERE started_at >= ?"
        runs_params = [] if not since_ts else [since_ts]
        run_stats = conn.execute(
            f"SELECT COUNT(*) AS n, "
            f"COALESCE(SUM(CASE WHEN ended_at IS NOT NULL THEN duration_s END),0) AS total_s, "
            f"COALESCE(AVG(CASE WHEN ended_at IS NOT NULL THEN duration_s END),0) AS avg_s "
            f"FROM runs{runs_where}",
            runs_params,
        ).fetchone()

        total_s = int(run_stats["total_s"] or 0)
        net = loot_rev - filament_cost - ammo_cost - expense_cost
        isk_per_hr = (net * 3600.0 / total_s) if total_s > 0 else 0.0

        open_run = conn.execute(
            "SELECT * FROM runs WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        current = None
        if open_run:
            current = {
                "system_name": open_run["system_name"],
                "started_at": open_run["started_at"],
                "elapsed_s": int(time.time()) - int(open_run["started_at"]),
            }
        return {
            "runs": int(run_stats["n"] or 0),
            "total_time_s": total_s,
            "avg_run_s": int(run_stats["avg_s"] or 0),
            "loot_revenue": loot_rev,
            "filament_cost": filament_cost,
            "ammo_cost": ammo_cost,
            "expense_cost": expense_cost,
            "restock_cost": filament_cost + ammo_cost,
            "total_cost": filament_cost + ammo_cost + expense_cost,
            "net_profit": net,
            "isk_per_hr": isk_per_hr,
            "current_run": current,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/sso/login")
def sso_login():
    state = _secrets.token_urlsafe(24)
    session["sso_state"] = state
    q = urlencode({
        "response_type": "code",
        "redirect_uri": CALLBACK_URL,
        "client_id": CLIENT_ID,
        "scope": EVE_SCOPE,
        "state": state,
    })
    return redirect(f"{EVE_SSO_AUTH}?{q}")


@app.route("/sso/callback")
def sso_callback():
    if request.args.get("state") != session.pop("sso_state", None):
        return "state mismatch", 400
    code = request.args.get("code")
    if not code:
        return "no code", 400
    r = requests.post(
        EVE_SSO_TOKEN,
        headers={
            "Authorization": f"Basic {sso_basic_auth()}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "login.eveonline.com",
        },
        data={"grant_type": "authorization_code", "code": code},
        timeout=15,
    )
    if r.status_code != 200:
        return f"token exchange failed: {r.text}", 400
    tok = r.json()
    v = requests.get(
        "https://login.eveonline.com/oauth/verify",
        headers={"Authorization": f"Bearer {tok['access_token']}"},
        timeout=15,
    )
    if v.status_code != 200:
        return "verify failed", 400
    info = v.json()
    store_tokens(
        int(info["CharacterID"]), info["CharacterName"],
        tok["access_token"], tok["refresh_token"], tok["expires_in"],
    )
    session["character_id"] = int(info["CharacterID"])
    session["character_name"] = info["CharacterName"]
    return redirect("/")


@app.route("/sso/logout")
def sso_logout():
    session.clear()
    conn = db_direct()
    try:
        conn.execute("DELETE FROM tokens")
        conn.commit()
    finally:
        conn.close()
    return redirect("/")


@app.route("/")
def index():
    tok_row = get_stored_tokens()
    if not tok_row:
        return render_template("index.html", logged_in=False, character_name=None,
                               stats=None, since_label="All time")
    stats = compute_stats()
    return render_template(
        "index.html",
        logged_in=True,
        character_name=tok_row["character_name"],
        stats=stats,
        since_label="All time",
    )


@app.route("/api/stats")
def api_stats():
    window = request.args.get("window", "all")
    windows = {"24h": 3600 * 24, "7d": 86400 * 7, "30d": 86400 * 30,
               "90d": 86400 * 90, "all": None}
    span = windows.get(window)
    since = None if span is None else int(time.time()) - span
    return jsonify(compute_stats(since))


@app.route("/runs")
def runs():
    conn = db_direct()
    try:
        rows = conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT 500"
        ).fetchall()
        return render_template("runs.html", runs=[dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/txns")
def txns():
    conn = db_direct()
    try:
        cat = request.args.get("cat")
        base = "SELECT * FROM transactions"
        params = []
        cat_expr = _effective_category_sql()
        if cat and cat != "all":
            base += f" WHERE {cat_expr} = ?"
            params.append(cat)
        base += " ORDER BY date DESC LIMIT 500"
        rows = conn.execute(base, params).fetchall()
        return render_template("txns.html",
                               txns=[dict(r) for r in rows],
                               current_cat=cat or "all")
    finally:
        conn.close()


@app.route("/api/txn/<int:txn_id>/category", methods=["POST"])
def api_txn_category(txn_id):
    new_cat = (request.json or {}).get("category", "").strip()
    if new_cat not in ("loot", "filament", "ammo", "expense", "other", ""):
        return jsonify({"error": "bad category"}), 400
    conn = db_direct()
    try:
        conn.execute(
            "UPDATE transactions SET manual_category=? WHERE transaction_id=?",
            (new_cat or None, txn_id),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/api/reclassify", methods=["POST"])
def api_reclassify():
    """Re-run auto classification on all transactions (useful after config changes)."""
    conn = db_direct()
    try:
        rows = conn.execute(
            "SELECT transaction_id, type_id, type_name FROM transactions"
        ).fetchall()
        for r in rows:
            conn.execute(
                "UPDATE transactions SET auto_category=? WHERE transaction_id=?",
                (classify(int(r["type_id"]), r["type_name"]), int(r["transaction_id"])),
            )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "count": len(rows)})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def _startup():
    init_db()
    try:
        load_classification_sets()
    except Exception as e:
        app.logger.warning("classification load failed: %s", e)
    try:
        load_abyss_systems()
    except Exception as e:
        app.logger.warning("abyss system load failed: %s", e)
    t1 = threading.Thread(target=poll_location_loop, daemon=True, name="loc-poll")
    t2 = threading.Thread(target=poll_wallet_loop, daemon=True, name="wallet-poll")
    t1.start()
    t2.start()


_startup()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5051))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False, use_reloader=False)
