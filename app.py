import base64
import functools
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(INSTANCE_DIR, "obsidian_wire.sqlite3")
SECRET_PATH = os.path.join(INSTANCE_DIR, "secret.key")
SESSION_COOKIE = "ow_session"
DEVICE_COOKIE = "ow_device"
SESSION_DAYS = 45
PBKDF2_ROUNDS = 390_000


app = Flask(__name__, instance_path=INSTANCE_DIR, instance_relative_config=True)
app.config["COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}


def _ensure_instance_dir() -> None:
    os.makedirs(INSTANCE_DIR, exist_ok=True)


def _load_secret() -> bytes:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret.encode("utf-8")

    _ensure_instance_dir()
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w", encoding="utf-8") as secret_file:
            secret_file.write(secrets.token_hex(64))
    with open(SECRET_PATH, "r", encoding="utf-8") as secret_file:
        return secret_file.read().strip().encode("utf-8")


SIGNING_SECRET = _load_secret()


def db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_error=None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "media-src 'self' blob:; "
        "base-uri 'none'; "
        "frame-ancestors 'none'",
    )
    return response


def init_db() -> None:
    _ensure_instance_dir()
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blind_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_uuid TEXT NOT NULL,
                recipient_uuid TEXT NOT NULL,
                aad TEXT NOT NULL,
                recipient_capsule TEXT NOT NULL,
                recipient_iv TEXT NOT NULL,
                recipient_ciphertext TEXT NOT NULL,
                sender_capsule TEXT NOT NULL,
                sender_iv TEXT NOT NULL,
                sender_ciphertext TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender_uuid) REFERENCES users(uuid) ON DELETE CASCADE,
                FOREIGN KEY(recipient_uuid) REFERENCES users(uuid) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_blind_messages_recipient
                ON blind_messages(recipient_uuid, created_at);

            CREATE INDEX IF NOT EXISTS idx_blind_messages_sender
                ON blind_messages(sender_uuid, created_at);
            """
        )
        connection.commit()
    finally:
        connection.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def encode_token(payload: dict) -> str:
    header = {"typ": "JWT", "alg": "HS256"}
    header_part = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signed = f"{header_part}.{payload_part}".encode("ascii")
    signature = hmac.new(SIGNING_SECRET, signed, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{b64url_encode(signature)}"


def decode_token(token: str) -> dict | None:
    try:
        header_part, payload_part, signature_part = token.split(".", 2)
        signed = f"{header_part}.{payload_part}".encode("ascii")
        expected = hmac.new(SIGNING_SECRET, signed, hashlib.sha256).digest()
        actual = b64url_decode(signature_part)
        if not hmac.compare_digest(expected, actual):
            return None
        payload = json.loads(b64url_decode(payload_part))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def device_hash(device_id: str) -> str:
    user_agent = request.headers.get("User-Agent", "")
    language = request.headers.get("Accept-Language", "")
    material = f"{device_id}|{user_agent}|{language}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return (
        f"pbkdf2_sha256${PBKDF2_ROUNDS}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(digest).decode('ascii')}"
    )


def verify_password(stored: str, password: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def set_auth_cookies(response, user: sqlite3.Row, remember: bool = True):
    device_id = request.cookies.get(DEVICE_COOKIE) or secrets.token_urlsafe(32)
    max_age = SESSION_DAYS * 24 * 60 * 60 if remember else 24 * 60 * 60
    expires_at = int(time.time()) + max_age
    payload = {
        "uuid": user["uuid"],
        "username": user["username"],
        "device": device_hash(device_id),
        "exp": expires_at,
    }
    token = encode_token(payload)
    cookie_options = {
        "httponly": True,
        "secure": app.config["COOKIE_SECURE"],
        "samesite": "Strict",
        "max_age": max_age,
        "path": "/",
    }
    response.set_cookie(DEVICE_COOKIE, device_id, **cookie_options)
    response.set_cookie(SESSION_COOKIE, token, **cookie_options)
    return response


def clear_auth_cookies(response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(DEVICE_COOKIE, path="/")
    return response


def get_current_user() -> sqlite3.Row | None:
    if hasattr(g, "current_user"):
        return g.current_user

    token = request.cookies.get(SESSION_COOKIE)
    device_id = request.cookies.get(DEVICE_COOKIE)
    payload = decode_token(token) if token and device_id else None
    if not payload or payload.get("device") != device_hash(device_id):
        g.current_user = None
        return None

    user = db().execute(
        "SELECT uuid, username, created_at FROM users WHERE uuid = ?",
        (payload.get("uuid"),),
    ).fetchone()
    g.current_user = user
    return user


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth_required"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _form_bool(name: str, default: bool = False) -> bool:
    value = request.form.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _normalize_username(username: str) -> str:
    return " ".join(username.strip().split())


@app.route("/")
def index():
    return redirect(url_for("chat" if get_current_user() else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if get_current_user():
        return redirect(url_for("chat"))

    error = None
    if request.method == "POST":
        username = _normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 28:
            error = "Use um nome entre 3 e 28 caracteres."
        elif len(password) < 10:
            error = "Use uma senha com pelo menos 10 caracteres."
        else:
            user_uuid = str(uuid.uuid4())
            try:
                db().execute(
                    "INSERT INTO users (uuid, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (user_uuid, username, hash_password(password), now_iso()),
                )
                db().commit()
                user = db().execute(
                    "SELECT uuid, username, created_at FROM users WHERE uuid = ?",
                    (user_uuid,),
                ).fetchone()
                response = make_response(redirect(url_for("chat")))
                return set_auth_cookies(response, user, remember=_form_bool("remember", True))
            except sqlite3.IntegrityError:
                error = "Esse nome já está em uso."

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect(url_for("chat"))

    error = None
    if request.method == "POST":
        username = _normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        user = db().execute(
            "SELECT uuid, username, password_hash, created_at FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if user and verify_password(user["password_hash"], password):
            response = make_response(redirect(url_for("chat")))
            return set_auth_cookies(response, user, remember=_form_bool("remember", True))
        error = "Nome ou senha inválidos."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    response = make_response(redirect(url_for("login")))
    return clear_auth_cookies(response)


@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html")


@app.get("/api/me")
@login_required
def api_me():
    user = get_current_user()
    return jsonify({"uuid": user["uuid"], "username": user["username"], "created_at": user["created_at"]})


@app.post("/api/contact-qr")
@login_required
def api_contact_qr():
    payload = request.get_json(silent=True) or {}
    qr_payload = _bounded_text(payload.get("payload"), "payload", 6000)
    if not qr_payload.startswith("OW1:"):
        return jsonify({"error": "invalid_qr_payload"}), 400

    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_L
    except ImportError:
        return jsonify({"error": "missing_qrcode_dependency"}), 500

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_L,
        box_size=6,
        border=2,
    )
    qr.add_data(qr_payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="#07100b", back_color="#eef7f0").convert("RGB")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    data_url = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    return jsonify({"data_url": data_url})


def _bounded_text(value, field: str, max_len: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        abort(make_response(jsonify({"error": f"invalid_{field}"}), 400))
    return value


@app.route("/api/messages", methods=["GET", "POST"])
@login_required
def api_messages():
    user = get_current_user()

    if request.method == "GET":
        rows = db().execute(
            """
            SELECT *
            FROM blind_messages
            WHERE sender_uuid = ? OR recipient_uuid = ?
            ORDER BY datetime(created_at) ASC, id ASC
            LIMIT 500
            """,
            (user["uuid"], user["uuid"]),
        ).fetchall()
        messages = []
        for row in rows:
            is_sender = row["sender_uuid"] == user["uuid"]
            messages.append(
                {
                    "id": row["id"],
                    "sender_uuid": row["sender_uuid"],
                    "recipient_uuid": row["recipient_uuid"],
                    "peer_uuid": row["recipient_uuid"] if is_sender else row["sender_uuid"],
                    "direction": "out" if is_sender else "in",
                    "copy": "sender" if is_sender else "recipient",
                    "aad": row["aad"],
                    "capsule": row["sender_capsule"] if is_sender else row["recipient_capsule"],
                    "iv": row["sender_iv"] if is_sender else row["recipient_iv"],
                    "ciphertext": row["sender_ciphertext"] if is_sender else row["recipient_ciphertext"],
                    "created_at": row["created_at"],
                }
            )
        return jsonify({"messages": messages})

    payload = request.get_json(silent=True) or {}
    recipient_uuid = _bounded_text(payload.get("recipient_uuid"), "recipient_uuid", 64)
    aad = _bounded_text(payload.get("aad"), "aad", 2048)
    recipient_copy = payload.get("recipient_copy") or {}
    sender_copy = payload.get("sender_copy") or {}

    recipient = db().execute(
        "SELECT uuid FROM users WHERE uuid = ?",
        (recipient_uuid,),
    ).fetchone()
    if recipient is None:
        return jsonify({"error": "recipient_not_found"}), 404

    values = {
        "recipient_capsule": _bounded_text(recipient_copy.get("capsule"), "recipient_capsule", 4096),
        "recipient_iv": _bounded_text(recipient_copy.get("iv"), "recipient_iv", 128),
        "recipient_ciphertext": _bounded_text(recipient_copy.get("ciphertext"), "recipient_ciphertext", 65536),
        "sender_capsule": _bounded_text(sender_copy.get("capsule"), "sender_capsule", 4096),
        "sender_iv": _bounded_text(sender_copy.get("iv"), "sender_iv", 128),
        "sender_ciphertext": _bounded_text(sender_copy.get("ciphertext"), "sender_ciphertext", 65536),
    }

    cursor = db().execute(
        """
        INSERT INTO blind_messages (
            sender_uuid, recipient_uuid, aad,
            recipient_capsule, recipient_iv, recipient_ciphertext,
            sender_capsule, sender_iv, sender_ciphertext,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["uuid"],
            recipient_uuid,
            aad,
            values["recipient_capsule"],
            values["recipient_iv"],
            values["recipient_ciphertext"],
            values["sender_capsule"],
            values["sender_iv"],
            values["sender_ciphertext"],
            now_iso(),
        ),
    )
    db().commit()
    return jsonify({"ok": True, "id": cursor.lastrowid}), 201


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True, "service": "obsidian-wire"})


with app.app_context():
    init_db()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=debug)
