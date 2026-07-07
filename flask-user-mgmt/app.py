from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import os

app = Flask(__name__)
app.secret_key = "dev-key-2025-secure"

DATABASE = 'users.db'


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库，创建用户表并插入默认用户（密码已哈希）"""
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
            ('admin', generate_password_hash('Admin@12345'), 'admin',
             'admin@example.com', '13800138000', 99999),
            ('alice', generate_password_hash('Alice@2025'), 'user',
             'alice@example.com', '13900139001', 100),
        ]
        conn.executemany(
            "INSERT INTO users (username, password_hash, role, email, phone, balance) "
            "VALUES (?, ?, ?, ?, ?, ?)", default_users
        )
        conn.commit()
    conn.close()


def validate_password_complexity(password):
    """
    密码复杂度校验：
    - 至少8个字符
    - 包含大写字母
    - 包含小写字母
    - 包含数字
    - 包含特殊符号
    """
    if len(password) < 8:
        return "密码长度不能少于8位"
    if not re.search(r'[A-Z]', password):
        return "密码必须包含大写字母"
    if not re.search(r'[a-z]', password):
        return "密码必须包含小写字母"
    if not re.search(r'[0-9]', password):
        return "密码必须包含数字"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\\/]', password):
        return "密码必须包含至少一个特殊符号"
    return None


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
        password = request.form.get("password", "")

        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], password):
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
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 密码复杂度校验
        pw_error = validate_password_complexity(password)
        if pw_error:
            return render_template("register.html", error=pw_error,
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

        # 插入新用户
        password_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, role, email, phone, balance) "
            "VALUES (?, ?, 'user', ?, ?, 0)",
            (username, password_hash, email, phone)
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
