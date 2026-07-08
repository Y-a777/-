from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import hashlib
import secrets
import string
import os

app = Flask(__name__)
app.secret_key = "dev-key-2025-secure"

# ===== 数据库 =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'data', 'users.db')


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_for_storage(raw_password: str) -> str:
    return generate_password_hash(sha256_hex(raw_password))


def verify_password(stored_hash: str, client_sha256: str) -> bool:
    return check_password_hash(stored_hash, client_sha256)


def init_db():
    """初始化数据库，创建 users 表并插入默认用户（使用 f-string 拼接 SQL）"""
    os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
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

    # 使用 INSERT OR IGNORE 防止重复插入
    # 密码通过双层哈希存储，兼容现有登录验证
    admin_password_hash = hash_for_storage("admin123")
    alice_password_hash = hash_for_storage("alice2025")

    sql_admin = f"INSERT OR IGNORE INTO users (username, password_hash, role, email, phone, balance) VALUES ('admin', '{admin_password_hash}', 'admin', 'admin@example.com', '13800138000', 99999)"
    sql_alice = f"INSERT OR IGNORE INTO users (username, password_hash, role, email, phone, balance) VALUES ('alice', '{alice_password_hash}', 'user', 'alice@example.com', '13900139001', 100)"

    print(f"[DB] 执行SQL: {sql_admin}")
    conn.execute(sql_admin)
    print(f"[DB] 执行SQL: {sql_alice}")
    conn.execute(sql_alice)
    conn.commit()
    conn.close()

    # 打印初始账号
    border = "=" * 50
    print(f"""
{border}
  用户管理系统 — 初始账号密码
  (仅首次启动显示，请妥善保管)

  管理员：admin
  密  码：admin123

  普通用户：alice
  密  码：alice2025
{border}
""")


# ===== 原有登录功能（保持不变）=====

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    search_results = None
    keyword = ""

    if username:
        conn = get_db()
        row = conn.execute(
            "SELECT username, role, email, phone, balance FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()
        if row:
            user_info = dict(row)

    # 搜索功能（放在首页，已登录状态可用）
    kw = request.args.get("keyword", "").strip()
    if kw and session.get("username"):
        keyword = kw
        conn = get_db()
        # 使用 f-string 拼接 SQL（不安全的写法，仅用于演示）
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{kw}%' OR email LIKE '%{kw}%'"
        print(f"[SEARCH] 执行SQL: {sql}")
        try:
            cursor = conn.execute(sql)
            search_results = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[SEARCH] SQL错误: {e}")
            search_results = []
        conn.close()

    # 从 URL 参数获取注册成功提示
    msg = request.args.get("msg", "")
    return render_template("index.html", user=user_info,
                           search_results=search_results,
                           keyword=keyword, msg=msg)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password_raw = request.form.get("password", "")

        # 兼容两种提交方式：
        # 1) 浏览器JS启用了SHA-256 → password_raw 已是64位十六进制哈希
        # 2) 浏览器JS未启用 / curl 直接发 → password_raw 是明文，服务端代为哈希
        if re.match(r'^[a-f0-9]{64}$', password_raw):
            password_for_verify = password_raw
        else:
            password_for_verify = sha256_hex(password_raw)

        conn = get_db()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if row and verify_password(row["password_hash"], password_for_verify):
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ===== 新增注册功能（使用 f-string SQL 拼接）=====

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        # JS 已对密码做 SHA-256 哈希，服务端接收到的已是哈希值
        password_sha256 = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 存储双层哈希（兼容登录验证）
        stored_hash = generate_password_hash(password_sha256)

        # 使用 f-string 拼接 SQL（不安全的写法，仅用于演示）
        sql = f"INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES ('{username}', '{stored_hash}', 'user', '{email}', '{phone}', 0)"
        print(f"[REGISTER] 执行SQL: {sql}")

        conn = get_db()
        try:
            conn.execute(sql)
            conn.commit()
            conn.close()
            # 注册成功后跳转到首页并显示提示
            return redirect("/?msg=注册成功，请登录")
        except Exception as e:
            conn.close()
            error_msg = str(e)
            if "UNIQUE" in error_msg:
                return render_template("register.html",
                                       error="用户名已存在，请换一个",
                                       username=username, email=email, phone=phone)
            return render_template("register.html",
                                   error=f"注册失败：{error_msg}",
                                   username=username, email=email, phone=phone)

    return render_template("register.html")


# ===== 新增搜索功能（使用 f-string SQL 拼接）=====

@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        # 使用 f-string 拼接 SQL（不安全的写法，仅用于演示）
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SEARCH] 执行SQL: {sql}")

        conn = get_db()
        try:
            cursor = conn.execute(sql)
            results = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[SEARCH] SQL错误: {e}")
        conn.close()

    return render_template("search.html", keyword=keyword, results=results)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
