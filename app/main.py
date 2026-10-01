import io
import time
from pathlib import Path

import qrcode
from pydantic import BaseModel
from fastapi import FastAPI, Request, Form, Depends, HTTPException, Header
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import auth, crypto, db
from app.services import log_action, notify_team

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="PassingThePass")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

db.init_db()

# in-memory store for pending 2FA logins (short-lived, server restart clears it -> fine for MVP)
PENDING_2FA = {}  # pending_id -> {"user_id", "team_id", "exp"}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def get_user_from_token(token: str):
    payload = auth.decode_token(token)
    if not payload:
        return None
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (payload["sub"],)).fetchone()
        return dict(row) if row else None


def current_user(request: Request):
    token = request.cookies.get(auth.SESSION_COOKIE)
    if not token:
        return None
    return get_user_from_token(token)


def require_user_api(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


# ---------------------------------------------------------------- pages ----

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    if user:
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("signup.html", {"request": request, "error": None})


@app.post("/signup")
def signup(request: Request, team_name_: str = Form(..., alias="team_name"), name: str = Form(...),
           email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    with db.get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return templates.TemplateResponse("signup.html", {"request": request, "error": "Email already registered."})
        invite_code = auth.new_invite_code()
        cur = conn.execute("INSERT INTO teams (name, invite_code) VALUES (?, ?)", (team_name_.strip(), invite_code))
        team_id = cur.lastrowid
        pw_hash = auth.hash_password(password)
        cur = conn.execute(
            "INSERT INTO users (team_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'owner')",
            (team_id, name.strip(), email, pw_hash),
        )
        user_id = cur.lastrowid
        log_action(conn, team_id, {"id": user_id, "name": name}, "team_created", team_name_, ip=client_ip(request))
        log_action(conn, team_id, {"id": user_id, "name": name}, "signup", email, ip=client_ip(request))
    token = auth.create_token(user_id, team_id)
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(auth.SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=auth.TOKEN_TTL_SECONDS)
    return resp


@app.get("/join", response_class=HTMLResponse)
def join_page(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("join.html", {"request": request, "error": None})


@app.post("/join")
def join(request: Request, invite_code: str = Form(...), name: str = Form(...), email: str = Form(...),
          password: str = Form(...)):
    email = email.strip().lower()
    with db.get_db() as conn:
        team = conn.execute("SELECT * FROM teams WHERE invite_code = ?", (invite_code.strip().upper(),)).fetchone()
        if not team:
            return templates.TemplateResponse("join.html", {"request": request, "error": "Invalid invite code."})
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            return templates.TemplateResponse("join.html", {"request": request, "error": "Email already registered."})
        pw_hash = auth.hash_password(password)
        cur = conn.execute(
            "INSERT INTO users (team_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'member')",
            (team["id"], name.strip(), email, pw_hash),
        )
        user_id = cur.lastrowid
        log_action(conn, team["id"], {"id": user_id, "name": name}, "member_joined", email, ip=client_ip(request))
        notify_team(conn, team["id"], f"{name.strip()} joined the team.", exclude_user_id=user_id)
    token = auth.create_token(user_id, team["id"])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(auth.SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=auth.TOKEN_TTL_SECONDS)
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not row or not auth.verify_password(password, row["password_hash"]):
            log_action(conn, row["team_id"] if row else 0, None, "login_failed", email, ip=client_ip(request))
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password."})
        user = dict(row)
        if user["totp_enabled"]:
            pending_id = auth.new_invite_code()
            PENDING_2FA[pending_id] = {"user_id": user["id"], "team_id": user["team_id"], "exp": time.time() + 300}
            resp = RedirectResponse(f"/login/2fa?pid={pending_id}", status_code=303)
            return resp
        log_action(conn, user["team_id"], user, "login_success", email, ip=client_ip(request))
    token = auth.create_token(user["id"], user["team_id"])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(auth.SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=auth.TOKEN_TTL_SECONDS)
    return resp


@app.get("/login/2fa", response_class=HTMLResponse)
def login_2fa_page(request: Request, pid: str):
    if pid not in PENDING_2FA:
        return RedirectResponse("/login")
    return templates.TemplateResponse("login_2fa.html", {"request": request, "pid": pid, "error": None})


@app.post("/login/2fa")
def login_2fa(request: Request, pid: str = Form(...), code: str = Form(...)):
    pending = PENDING_2FA.get(pid)
    if not pending or pending["exp"] < time.time():
        PENDING_2FA.pop(pid, None)
        return RedirectResponse("/login")
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (pending["user_id"],)).fetchone()
        user = dict(row)
        if not auth.verify_totp(user["totp_secret"], code):
            log_action(conn, user["team_id"], user, "login_2fa_failed", user["email"], ip=client_ip(request))
            return templates.TemplateResponse("login_2fa.html", {"request": request, "pid": pid, "error": "Invalid code."})
        log_action(conn, user["team_id"], user, "login_success", user["email"], ip=client_ip(request))
    PENDING_2FA.pop(pid, None)
    token = auth.create_token(user["id"], user["team_id"])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(auth.SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=auth.TOKEN_TTL_SECONDS)
    return resp


@app.get("/logout")
def logout(request: Request):
    user = current_user(request)
    if user:
        with db.get_db() as conn:
            log_action(conn, user["team_id"], user, "logout", user["email"], ip=client_ip(request))
    resp = RedirectResponse("/login")
    resp.delete_cookie(auth.SESSION_COOKIE)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        items = conn.execute(
            "SELECT id, title, username, url, updated_at FROM vault_items WHERE team_id = ? ORDER BY title",
            (user["team_id"],),
        ).fetchall()
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "items": items})


@app.post("/vault/create")
def vault_create(request: Request, title: str = Form(...), username: str = Form(""), url: str = Form(""),
                  notes: str = Form(""), secret: str = Form(...)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    enc = crypto.encrypt(secret)
    with db.get_db() as conn:
        cur = conn.execute(
            "INSERT INTO vault_items (team_id, title, username, url, notes, secret_enc, created_by, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user["team_id"], title.strip(), username.strip(), url.strip(), notes.strip(), enc, user["id"], user["id"]),
        )
        log_action(conn, user["team_id"], user, "item_created", title, ip=client_ip(request))
        notify_team(conn, user["team_id"], f"{user['name']} added \"{title}\" to the vault.", exclude_user_id=user["id"])
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/vault/{item_id}/update")
def vault_update(request: Request, item_id: int, title: str = Form(...), username: str = Form(""),
                  url: str = Form(""), notes: str = Form(""), secret: str = Form("")):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        item = conn.execute("SELECT * FROM vault_items WHERE id = ? AND team_id = ?", (item_id, user["team_id"])).fetchone()
        if not item:
            raise HTTPException(404)
        if secret.strip():
            enc = crypto.encrypt(secret)
            conn.execute(
                "UPDATE vault_items SET title=?, username=?, url=?, notes=?, secret_enc=?, updated_by=?, updated_at=datetime('now') WHERE id=?",
                (title.strip(), username.strip(), url.strip(), notes.strip(), enc, user["id"], item_id),
            )
        else:
            conn.execute(
                "UPDATE vault_items SET title=?, username=?, url=?, notes=?, updated_by=?, updated_at=datetime('now') WHERE id=?",
                (title.strip(), username.strip(), url.strip(), notes.strip(), user["id"], item_id),
            )
        log_action(conn, user["team_id"], user, "item_updated", title, ip=client_ip(request))
        notify_team(conn, user["team_id"], f"{user['name']} updated \"{title}\".", exclude_user_id=user["id"])
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/vault/{item_id}/delete")
def vault_delete(request: Request, item_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        item = conn.execute("SELECT * FROM vault_items WHERE id = ? AND team_id = ?", (item_id, user["team_id"])).fetchone()
        if not item:
            raise HTTPException(404)
        conn.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))
        log_action(conn, user["team_id"], user, "item_deleted", item["title"], ip=client_ip(request))
        notify_team(conn, user["team_id"], f"{user['name']} deleted \"{item['title']}\".", exclude_user_id=user["id"])
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/vault/{item_id}/reveal")
def vault_reveal(request: Request, item_id: int):
    user = current_user(request)
    if not user:
        raise HTTPException(401)
    with db.get_db() as conn:
        item = conn.execute("SELECT * FROM vault_items WHERE id = ? AND team_id = ?", (item_id, user["team_id"])).fetchone()
        if not item:
            raise HTTPException(404)
        secret = crypto.decrypt(item["secret_enc"])
        log_action(conn, user["team_id"], user, "item_viewed", item["title"], ip=client_ip(request))
    return JSONResponse({"secret": secret})


@app.get("/settings/2fa", response_class=HTMLResponse)
def settings_2fa(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    qr_uri = None
    secret = user["totp_secret"]
    if not user["totp_enabled"]:
        if not secret:
            secret = auth.new_totp_secret()
            with db.get_db() as conn:
                conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
        qr_uri = auth.totp_uri(secret, user["email"])
    return templates.TemplateResponse("settings_2fa.html", {
        "request": request, "user": user, "qr_uri": qr_uri, "secret": secret,
    })


@app.get("/settings/2fa/qr.png")
def settings_2fa_qr(request: Request):
    user = current_user(request)
    if not user or user["totp_enabled"] or not user["totp_secret"]:
        raise HTTPException(404)
    uri = auth.totp_uri(user["totp_secret"], user["email"])
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.post("/settings/2fa/enable")
def settings_2fa_enable(request: Request, code: str = Form(...)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        row = conn.execute("SELECT totp_secret FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not auth.verify_totp(row["totp_secret"], code):
            qr_uri = auth.totp_uri(row["totp_secret"], user["email"])
            return templates.TemplateResponse("settings_2fa.html", {
                "request": request, "user": user, "qr_uri": qr_uri, "secret": row["totp_secret"],
                "error": "Invalid code, try again.",
            })
        conn.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user["id"],))
        log_action(conn, user["team_id"], user, "2fa_enabled", user["email"], ip=client_ip(request))
    return RedirectResponse("/settings/2fa?enabled=1", status_code=303)


@app.post("/settings/2fa/disable")
def settings_2fa_disable(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        conn.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?", (user["id"],))
        log_action(conn, user["team_id"], user, "2fa_disabled", user["email"], ip=client_ip(request))
    return RedirectResponse("/settings/2fa", status_code=303)


@app.get("/team", response_class=HTMLResponse)
def team_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        members = conn.execute(
            "SELECT id, name, email, role, totp_enabled, created_at FROM users WHERE team_id = ? ORDER BY created_at",
            (user["team_id"],),
        ).fetchall()
        team = conn.execute("SELECT * FROM teams WHERE id = ?", (user["team_id"],)).fetchone()
    return templates.TemplateResponse("team.html", {"request": request, "user": user, "members": members, "team": team})


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login")
    with db.get_db() as conn:
        logs = conn.execute(
            "SELECT * FROM audit_log WHERE team_id = ? ORDER BY id DESC LIMIT 200",
            (user["team_id"],),
        ).fetchall()
    return templates.TemplateResponse("audit.html", {"request": request, "user": user, "logs": logs})


@app.get("/api/notifications")
def api_notifications(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401)
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT id, message, read, created_at FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 20",
            (user["id"],),
        ).fetchall()
        unread = conn.execute(
            "SELECT COUNT(*) c FROM notifications WHERE user_id = ? AND read = 0", (user["id"],)
        ).fetchone()["c"]
    return JSONResponse({
        "unread": unread,
        "items": [{"id": r["id"], "message": r["message"], "read": bool(r["read"]), "created_at": r["created_at"]} for r in rows],
    })


@app.post("/api/notifications/read")
def api_notifications_read(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401)
    with db.get_db() as conn:
        conn.execute("UPDATE notifications SET read = 1 WHERE user_id = ?", (user["id"],))
    return JSONResponse({"ok": True})


# ------------------------------------------------------- JSON Team API -----
# Bearer-token API for team integrations / mobile clients.

@app.post("/api/auth/login")
def api_login(request: Request, email: str = Form(...), password: str = Form(...), totp_code: str = Form("")):
    email = email.strip().lower()
    with db.get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not row or not auth.verify_password(password, row["password_hash"]):
            log_action(conn, row["team_id"] if row else 0, None, "api_login_failed", email, ip=client_ip(request))
            raise HTTPException(401, "Invalid credentials")
        user = dict(row)
        if user["totp_enabled"]:
            if not totp_code or not auth.verify_totp(user["totp_secret"], totp_code):
                return JSONResponse({"requires_2fa": True}, status_code=401)
        log_action(conn, user["team_id"], user, "api_login_success", email, ip=client_ip(request))
    token = auth.create_token(user["id"], user["team_id"])
    return JSONResponse({
        "token": token,
        "token_type": "bearer",
        "expires_in": auth.TOKEN_TTL_SECONDS,
        "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
    })


@app.get("/api/team/members")
def api_team_members(user=Depends(require_user_api)):
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, email, role, totp_enabled FROM users WHERE team_id = ?", (user["team_id"],)
        ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/vault")
def api_vault_list(user=Depends(require_user_api)):
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT id, title, username, url, updated_at FROM vault_items WHERE team_id = ? ORDER BY title",
            (user["team_id"],),
        ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/vault/{item_id}")
def api_vault_get(item_id: int, request: Request, user=Depends(require_user_api)):
    with db.get_db() as conn:
        item = conn.execute("SELECT * FROM vault_items WHERE id = ? AND team_id = ?", (item_id, user["team_id"])).fetchone()
        if not item:
            raise HTTPException(404)
        secret = crypto.decrypt(item["secret_enc"])
        log_action(conn, user["team_id"], user, "api_item_viewed", item["title"], ip=client_ip(request))
    return JSONResponse({
        "id": item["id"], "title": item["title"], "username": item["username"],
        "url": item["url"], "notes": item["notes"], "secret": secret,
    })


class VaultItemIn(BaseModel):
    title: str
    secret: str
    username: str = ""
    url: str = ""
    notes: str = ""


@app.post("/api/vault")
def api_vault_create(request: Request, item: VaultItemIn, user=Depends(require_user_api)):
    enc = crypto.encrypt(item.secret)
    with db.get_db() as conn:
        cur = conn.execute(
            "INSERT INTO vault_items (team_id, title, username, url, notes, secret_enc, created_by, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user["team_id"], item.title.strip(), item.username.strip(), item.url.strip(), item.notes.strip(),
             enc, user["id"], user["id"]),
        )
        new_id = cur.lastrowid
        log_action(conn, user["team_id"], user, "api_item_created", item.title, ip=client_ip(request))
        notify_team(conn, user["team_id"], f"{user['name']} added \"{item.title}\" to the vault.", exclude_user_id=user["id"])
    return JSONResponse({"id": new_id, "title": item.title}, status_code=201)


@app.get("/api/audit")
def api_audit(user=Depends(require_user_api)):
    with db.get_db() as conn:
        logs = conn.execute(
            "SELECT * FROM audit_log WHERE team_id = ? ORDER BY id DESC LIMIT 100", (user["team_id"],)
        ).fetchall()
    return JSONResponse([dict(r) for r in logs])
