from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import hashlib
import secrets
import string

app = Flask(__name__)
app.secret_key = "dev-key-2025-secure"

DATABASE = 'users.db'

# 初始用户的无规律随机密码（仅首次初始化时使用，之后只存哈希）
_INITIAL_ADMIN_PW = "Nbf5O%jJnEg&&e"
_INITIAL_ALICE_PW = "GIdgVQa3D%i@Li"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def sha256_hex(text: str) -> str:
    """返回字符串的 SHA-256 十六进制摘要（与服务端 JS 一致）"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_for_storage(raw_password: str) -> str:
    """
    双层哈希：先用 SHA-256 摘要（模拟客户端哈希），
    再用 werkzeug pbkdf2:sha256 加盐哈希存储。
    """
    return generate_password_hash(sha256_hex(raw_password))


def verify_password(stored_hash: str, client_sha256: str) -> bool:
    """验证客户端传来的 SHA-256 是否匹配存储的双层哈希"""
    return check_password_hash(stored_hash, client_sha256)


def init_db():
    """初始化数据库，创建用户表并插入默认用户（双层哈希）"""
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        email TEXT,
        phone TEXT,
        balance REAL DEFAULT 0
    )''')

    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        default_users = [
            ('admin', hash_for_storage(_INITIAL_ADMIN_PW), 'admin',
             'admin@example.com', '13800138000', 99999),
            ('alice', hash_for_storage(_INITIAL_ALICE_PW), 'user',
             'alice@example.com', '13900139001', 100),
        ]
        conn.executemany(
            "INSERT INTO users (username, password_hash, role, email, phone, balance) "
            "VALUES (?, ?, ?, ?, ?, ?)", default_users
        )
        conn.commit()

        # 仅在首次初始化时打印密码到控制台
        border = "=" * 50
        print(f"""
{border}
  用户管理系统 — 初始账号密码
  (仅首次启动显示，请妥善保管)

  管理员：admin
  密  码：{_INITIAL_ADMIN_PW}

  普通用户：alice
  密  码：{_INITIAL_ALICE_PW}
{border}
""")
    conn.close()


# ===== 路由 =====

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        conn = get_db()
        row = conn.execute(
            "SELECT username, role, email, phone, balance FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()
        if row:
            user_info = dict(row)
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        # 注意：password 字段此时已经是 JS SHA-256 后的值（64位十六进制字符串）
        password_sha256 = request.form.get("password", "")

        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if row and verify_password(row["password_hash"], password_sha256):
            session["username"] = username
            user_info = {
                "username": row["username"],
                "role": row["role"],
                "email": row["email"],
                "phone": row["phone"],
                "balance": row["balance"],
            }
            return render_template("index.html", user=user_info)

        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        # password 字段已是 JS SHA-256 后的值
        password_sha256 = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 服务端兜底：SHA-256 哈希值必须是 64 位十六进制
        if not re.match(r'^[a-f0-9]{64}$', password_sha256):
            return render_template("register.html",
                                   error="密码格式异常，请启用 JavaScript",
                                   username=username, email=email, phone=phone)

        # 检查用户名是否已存在
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            conn.close()
            return render_template("register.html",
                                   error="用户名已存在，请换一个",
                                   username=username, email=email, phone=phone)

        # 存储双层哈希
        stored_hash = generate_password_hash(password_sha256)
        conn.execute(
            "INSERT INTO users (username, password_hash, role, email, phone, balance) "
            "VALUES (?, ?, 'user', ?, ?, 0)",
            (username, stored_hash, email, phone)
        )
        conn.commit()
        conn.close()

        session["username"] = username
        return redirect("/")

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
