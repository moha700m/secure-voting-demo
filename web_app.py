"""Small Flask web version of the voting system (DEMO ONLY).

It uses the SAME Python modules as the desktop app (voting.py, admin.py, auth.py,
tokens.py, crypto_utils.py). Only the interface is different.
Run locally:  python web_app.py   then open http://127.0.0.1:5000
"""
import os
import shutil
import threading
from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template_string, request

import admin
from voting import Election, VoteError

DEMO_PASSPHRASE = "demo-admin-2026"  # shown on the page on purpose (demo)
# Vercel only lets us write to /tmp, so the demo data lives there (and is temporary)
DATA_DIR = "/tmp/secure-voting-data" if os.environ.get("VERCEL") else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "web_data")

app = Flask(__name__)
_lock = threading.Lock()
_election = None


def reset_demo():
    global _election
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    e = Election(DATA_DIR)
    e.setup(DEMO_PASSPHRASE, deadline=datetime.now() + timedelta(days=7))
    _election = e
    return e


def election():
    """Return the election, creating it on first use (or after a cold start)."""
    global _election
    with _lock:
        if _election is None:
            if os.path.exists(os.path.join(DATA_DIR, "election.json")):
                _election = Election(DATA_DIR)
                _election.unlock(DEMO_PASSPHRASE)
            else:
                reset_demo()
        return _election


def state(e):
    from storage import connect
    conn = connect(e.data_dir)
    issued = conn.execute("SELECT COUNT(*) FROM main.students WHERE token_issued=1").fetchone()[0]
    cast = conn.execute("SELECT COUNT(*) FROM vot.votes").fetchone()[0]
    conn.close()
    d = e.deadline()
    return {"open": e.is_open(), "deadline": d.strftime("%Y-%m-%d %H:%M") if d else None,
            "candidates": e.candidates, "tokens_issued": issued, "votes_cast": cast}


def ok(**kw):
    return jsonify(ok=True, **kw)


def fail(msg, code=400):
    return jsonify(ok=False, error=msg), code


# ------------------------- API -------------------------
@app.get("/api/state")
def api_state():
    return ok(**state(election()))


@app.post("/api/login")
def api_login():
    b = request.get_json(force=True, silent=True) or {}
    try:
        token = election().login_and_get_token(str(b.get("student_id", "")).strip(), str(b.get("password", "")))
    except VoteError as err:
        return fail(str(err), 403)
    return ok(token=token)


@app.post("/api/vote")
def api_vote():
    b = request.get_json(force=True, silent=True) or {}
    e = election()
    if e.vote_key is None and e.is_open():
        e.unlock(DEMO_PASSPHRASE)  # demo only: key is reloaded after a server restart
    try:
        e.cast_vote(str(b.get("token", "")).strip(), str(b.get("candidate", "")))
    except VoteError as err:
        return fail(str(err), 409)
    return ok(message="Vote recorded")


def check_pass(b):
    from crypto_utils import unwrap_vote_key
    unwrap_vote_key(DATA_DIR, str(b.get("passphrase", "")))  # raises ValueError if wrong


@app.post("/api/admin/<action>")
def api_admin(action):
    b = request.get_json(force=True, silent=True) or {}
    e = election()
    try:
        if action == "deadline":
            check_pass(b)
            d = datetime.fromisoformat(str(b.get("deadline", "")).strip())
            if d.tzinfo:  # convert to server local time, our code uses naive local times
                d = d.astimezone().replace(tzinfo=None)
            admin.set_deadline(e, d)
            return ok(**state(e))
        if action == "close":
            check_pass(b)
            admin.close_voting(e)
            return ok(**state(e))
        if action == "count":
            counts = admin.count_votes(e, str(b.get("passphrase", "")))
            kind, names = admin.winner(counts)
            return ok(counts=counts, result={"kind": kind, "names": names})
    except admin.AdminError as err:
        return fail(str(err), 403)
    except ValueError as err:
        return fail(str(err), 401)
    return fail("Unknown action", 404)


@app.get("/api/votes-table")
def api_votes_table():
    """Shows what is really stored in votes.db (only random id, nonce, ciphertext)."""
    import sqlite3
    db = sqlite3.connect(os.path.join(election().data_dir, "votes.db"))
    cols = [r[1] for r in db.execute("PRAGMA table_info(votes)")]
    rows = [[v.hex()[:24] if isinstance(v, bytes) else v[:16] for v in r]
            for r in db.execute("SELECT * FROM votes LIMIT 5")]
    db.close()
    return ok(columns=cols, rows=rows)


@app.post("/api/reset")
def api_reset():
    with _lock:
        e = reset_demo()
    return ok(**state(e))


@app.get("/")
def index():
    return render_template_string(PAGE)


PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_page.html"), encoding="utf-8").read()

if __name__ == "__main__":
    app.run(debug=False, threaded=True)
