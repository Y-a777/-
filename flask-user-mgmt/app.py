from flask import Flask, render_template, request, redirect, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import re
import json
import hashlib
import secrets
import string
import os
import uuid
import urllib.request
import urllib.error
import subprocess
import platform

app = Flask(__name__)
app.secret_key = "dev-key-2025-secure"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# SameSite Cookie 设置
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_HTTPONLY'] = True


def generate_csrf_token():
    """生成一次性 CSRF Token 并存入 session"""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token


def validate_csrf_token():
    """校验表单提交的 CSRF Token 是否与 session 中的一致"""
    token = request.form.get('csrf_token', '')
    stored = session.get('csrf_token')
    if not token or not stored or token != stored:
        return False
    # 一次性使用，校验后立即清除
    session.pop('csrf_token', None)
    return True


def get_current_user_id():
    """根据 session 中的 username 获取当前登录用户的 ID"""
    username = session.get("username")
    if not username:
        return None
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row["id"] if row else None


@app.context_processor
def inject_current_user():
    """向所有模板注入当前登录用户信息和 CSRF Token"""
    user_id = get_current_user_id()
    csrf_token = generate_csrf_token()
    return dict(current_user_id=user_id, csrf_token=csrf_token)

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
            "SELECT id, username, role, email, phone, balance FROM users WHERE username = ?",
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
        # 使用参数化查询防止 SQL 注入
        like_param = f"%{kw}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SEARCH] 执行SQL: {sql} (参数: {like_param})")
        try:
            cursor = conn.execute(sql, (like_param, like_param))
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

        if not validate_csrf_token():
            return render_template("login.html", error="CSRF Token 无效，请刷新页面重试")

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

        if not validate_csrf_token():
            return render_template("register.html",
                                   error="CSRF Token 无效，请刷新页面重试",
                                   username=username, email=email, phone=phone)

        # 输入校验：防止包含SQL特殊字符的恶意输入
        import re
        if re.search(r"[';\"\\%_]|--|\.\.", username):
            return render_template("register.html",
                                   error="用户名包含非法字符（不允许使用引号、分号、反斜线等）",
                                   username=username, email=email, phone=phone)
        if email and re.search(r"[';\"\\%_]|--", email):
            return render_template("register.html",
                                   error="邮箱包含非法字符",
                                   username=username, email=email, phone=phone)
        if phone and not re.match(r'^[0-9+\-\s()]+$', phone):
            return render_template("register.html",
                                   error="手机号格式不正确",
                                   username=username, email=email, phone=phone)

        # 存储双层哈希（兼容登录验证）
        stored_hash = generate_password_hash(password_sha256)

        # 使用参数化查询防止 SQL 注入
        sql = "INSERT INTO users (username, password_hash, role, email, phone, balance) VALUES (?, ?, 'user', ?, ?, 0)"
        print(f"[REGISTER] 执行SQL: {sql} (参数: {username}, {email}, {phone})")

        conn = get_db()
        try:
            conn.execute(sql, (username, stored_hash, email, phone))
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
        # 使用参数化查询防止 SQL 注入
        like_param = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SEARCH] 执行SQL: {sql} (参数: {like_param})")

        conn = get_db()
        try:
            cursor = conn.execute(sql, (like_param, like_param))
            results = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[SEARCH] SQL错误: {e}")
        conn.close()

    return render_template("search.html", keyword=keyword, results=results)


# ===== 头像上传功能（安全修复后）=====

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 允许的图片扩展名
ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

# 常见图片格式的文件头（magic bytes）
MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n': '.png',
    b'\xff\xd8\xff': '.jpg',
    b'GIF87a': '.gif',
    b'GIF89a': '.gif',
    b'RIFF': '.webp',  # WEBP 以 RIFF 开头
}


def allowed_file(filename):
    """检查文件扩展名是否在白名单内"""
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


def validate_magic_bytes(data):
    """验证文件头 magic bytes 是否为合法图片格式"""
    for magic, ext in MAGIC_BYTES.items():
        if data.startswith(magic):
            return True
    return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    # 需要登录才能访问
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件上传")

        if not validate_csrf_token():
            return render_template("upload.html", error="CSRF Token 无效，请刷新页面重试")

        filename = file.filename

        # ① 检查文件扩展名
        if not allowed_file(filename):
            return render_template("upload.html", error="不支持的文件类型，仅允许图片文件（png/jpg/gif/webp）")

        # ② 检查文件内容（magic bytes），防止伪装扩展名
        file.seek(0)
        header = file.read(16)
        if not validate_magic_bytes(header):
            return render_template("upload.html", error="文件内容与图片格式不匹配，请上传有效图片")

        # ③ 使用 UUID 重命名文件，防止路径遍历和同名覆盖
        file.seek(0)
        _, ext = os.path.splitext(filename.lower())
        safe_filename = str(uuid.uuid4()) + ext
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        file.save(filepath)

        file_url = f"/uploads/{safe_filename}"
        return render_template("upload.html", file_url=file_url,
                               filename=safe_filename, original_name=filename)

    return render_template("upload.html")


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """提供上传文件访问，设置 Content-Disposition 防止 XSS"""
    return send_from_directory(UPLOAD_FOLDER, filename,
                               mimetype='image/png',
                               as_attachment=False,
                               download_name=filename)


# ===== 个人中心与充值功能 =====

@app.route("/profile", methods=["GET"])
def profile():
    if "username" not in session:
        return redirect("/login")

    # 从 session 获取当前登录用户信息（BL-01 修复：不从 URL 参数获取 user_id）
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email, phone, balance FROM users WHERE username = ?",
        (session["username"],)
    ).fetchone()
    conn.close()

    if not row:
        return render_template("profile.html", error="用户不存在", user=None)

    return render_template("profile.html", user=dict(row))


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")

    if not validate_csrf_token():
        return render_template("profile.html",
                               error="CSRF Token 无效，请刷新页面重试",
                               user=get_current_user_profile())

    # BL-02 修复：不从表单获取 user_id，使用当前登录用户
    current_user_id = get_current_user_id()
    if current_user_id is None:
        return redirect("/login")

    amount = request.form.get("amount", "0")

    try:
        amount_val = float(amount)
    except ValueError:
        amount_val = 0

    # BL-03 修复：金额必须大于 0
    if amount_val <= 0:
        return render_template("profile.html",
                               error="充值金额必须大于 0",
                               user=get_current_user_profile())

    conn = get_db()
    conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
                 (amount_val, current_user_id))
    conn.commit()
    conn.close()

    return redirect(f"/profile")


def get_current_user_profile():
    """获取当前登录用户的个人资料"""
    username = session.get("username")
    if not username:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email, phone, balance FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ===== 动态页面加载功能 =====

@app.route("/page", methods=["GET"])
def dynamic_page():
    if "username" not in session:
        return redirect("/login")

    name = request.args.get("name", "")

    # 获取当前登录用户信息
    user_info = None
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role, email, phone, balance FROM users WHERE username = ?",
        (session["username"],)
    ).fetchone()
    conn.close()
    if row:
        user_info = dict(row)

    if not name:
        return render_template("index.html", user=user_info, page_error="页面名称不能为空", page_content=None)

    # 路径遍历防护：禁止包含 ../ 的路径
    if ".." in name or name.startswith("/"):
        return render_template("index.html", user=user_info, page_error="非法的页面名称", page_content=None)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    pages_dir = os.path.join(base_dir, "pages")
    filepath = os.path.join(pages_dir, name)

    # 仅允许 .html 文件（自动补后缀）
    if not filepath.endswith(".html"):
        filepath += ".html"

    # 规范化路径并验证是否仍在 pages/ 目录内
    real_path = os.path.realpath(filepath)
    real_pages_dir = os.path.realpath(pages_dir)
    if not real_path.startswith(real_pages_dir + os.sep) and real_path != real_pages_dir:
        return render_template("index.html", user=user_info, page_error="非法的页面名称", page_content=None)

    content = None
    if os.path.isfile(real_path):
        with open(real_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        return render_template("index.html", user=user_info, page_error="页面不存在", page_content=None)

    return render_template("index.html", user=user_info, page_content=content)


# ===== 密码修改功能 =====

@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect("/login")

    if not validate_csrf_token():
        user = get_current_user_profile()
        return render_template("profile.html",
                               error="CSRF Token 无效，请刷新页面重试",
                               user=user)

    session_username = session.get("username", "")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if not old_password or not new_password:
        user = get_current_user_profile()
        return render_template("profile.html",
                               error="原密码和新密码不能为空",
                               user=user)

    # 验证原密码
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (session_username,)
    ).fetchone()
    conn.close()

    if not row:
        return render_template("profile.html",
                               error="用户不存在",
                               user=get_current_user_profile())

    # 兼容 JS SHA-256 和明文
    if re.match(r'^[a-f0-9]{64}$', old_password):
        old_pw_to_check = old_password
    else:
        old_pw_to_check = sha256_hex(old_password)

    if not verify_password(row["password_hash"], old_pw_to_check):
        return render_template("profile.html",
                               error="原密码错误",
                               user=get_current_user_profile())

    # 更新密码
    new_hash = hash_for_storage(new_password)
    conn = get_db()
    conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                 (new_hash, session_username))
    conn.commit()
    conn.close()

    return redirect("/profile")


# ===== URL 抓取功能（SSRF 安全修复）=====

import ipaddress
import socket


def is_private_ip(ip_str):
    """检查 IP 是否为内网/私有地址"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # 私有地址范围
        if ip.is_private:
            return True
        # 回环地址
        if ip.is_loopback:
            return True
        # 链路本地地址（含云元数据 169.254.169.254）
        if ip.is_link_local:
            return True
        # 多播地址
        if ip.is_multicast:
            return True
        # 保留地址
        if ip.is_reserved:
            return True
        # 额外云元数据地址
        if str(ip) == "100.100.100.200":
            return True
        return False
    except ValueError:
        return False


def resolve_and_check(url):
    """解析 URL 的域名获取 IP，检查是否为内网地址"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return "无法解析 URL 主机名"

    # 允许的协议
    if parsed.scheme not in ("http", "https"):
        return f"不支持的协议：{parsed.scheme}，仅允许 http/https"

    # 检查 hostname 是否已经是 IP
    try:
        ipaddress.ip_address(hostname)
        ip_str = hostname
    except ValueError:
        # 域名解析
        try:
            ip_str = socket.gethostbyname(hostname)
        except socket.gaierror:
            return f"无法解析域名：{hostname}"

    if is_private_ip(ip_str):
        return f"禁止访问内网地址：{ip_str}"

    return None


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect("/login")

    target_url = request.form.get("url", "").strip()

    if not target_url:
        return render_template("index.html",
                               fetch_result=None,
                               user=get_current_user_profile())

    # SSRF 防护：协议校验 + 内网地址拦截
    error_msg = resolve_and_check(target_url)
    if error_msg:
        result = {
            "status": "拒绝",
            "content": error_msg,
            "error": True
        }
        return render_template("index.html",
                               fetch_result=result,
                               user=get_current_user_profile())

    result = {}
    try:
        req = urllib.request.Request(target_url)
        with urllib.request.urlopen(req, timeout=10) as response:
            # 检查最终响应的 IP（防止 302 跳转到内网）
            final_url = response.geturl()
            redirect_error = resolve_and_check(final_url)
            if redirect_error:
                result = {
                    "status": "拒绝",
                    "content": f"跳转目标被拦截：{redirect_error}",
                    "error": True
                }
                return render_template("index.html",
                                       fetch_result=result,
                                       user=get_current_user_profile())

            result["status"] = response.getcode()
            content = response.read().decode("utf-8", errors="replace")

            # HTML 内容完整抓取用于渲染，非 HTML 截断到 5000
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type:
                result["content"] = content[:100000]
                result["truncated"] = len(content) > 100000
                result["is_html"] = True
            else:
                result["content"] = content[:5000]
                result["truncated"] = len(content) > 5000

    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["content"] = str(e)
        result["error"] = True
    except Exception as e:
        result["status"] = "错误"
        result["content"] = str(e)
        result["error"] = True

    return render_template("index.html",
                           fetch_result=result,
                           user=get_current_user_profile())


# ===== Ping 网络诊断功能（命令注入修复）=====

import socket


def is_valid_host(hostname):
    """验证输入是否为合法的 IP 地址或域名，防止命令注入"""
    # 禁止包含 shell 特殊字符
    dangerous_chars = set(";|&`$(){}[]<>!#~'\"\\")
    if any(c in hostname for c in dangerous_chars):
        return False

    # 允许合法 IP 地址
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # 允许合法域名（字母、数字、点、短横）
    # 简单域名格式：example.com, www.example.com
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', hostname):
        return True

    return False


@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect("/login")

    result = None
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            if not is_valid_host(ip):
                result = f"非法输入：'{ip}' 不是有效的 IP 地址或域名"
            else:
                try:
                    # 使用参数列表形式，避免 shell 注入
                    output = subprocess.check_output(
                        ["ping", "-c", "3", ip],
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                    result = output.decode("utf-8", errors="replace")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace") if e.output else f"命令执行失败，返回码：{e.returncode}"
                except subprocess.TimeoutExpired:
                    result = "Ping 超时（30秒）"
                except Exception as e:
                    result = f"执行错误：{str(e)}"

    return render_template("ping.html", result=result)


# ===== XML 数据导入功能（XXE 安全修复）=====

# 允许 XML SYSTEM 实体读取的目录白名单
ALLOWED_XML_READ_DIRS = [
    os.path.realpath(BASE_DIR),                          # 项目根目录
    os.path.realpath(os.path.join(BASE_DIR, 'pages')),   # pages 目录
    os.path.realpath(os.path.join(BASE_DIR, 'data')),    # data 目录
]

# 最大文件读取大小（4KB）
MAX_XML_FILE_READ = 4096


def is_allowed_xml_path(filepath):
    """验证文件路径是否在白名单目录内，防止路径遍历"""
    # 如果是相对路径，基于 BASE_DIR 解析
    if not os.path.isabs(filepath):
        filepath = os.path.join(BASE_DIR, filepath)
    real_path = os.path.realpath(filepath)
    for allowed_dir in ALLOWED_XML_READ_DIRS:
        if real_path.startswith(allowed_dir + os.sep) or real_path == allowed_dir:
            # 限制文件大小（已在调用处限制）
            return True
    return False


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if "username" not in session:
        return redirect("/login")

    result = None
    error = None

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "").strip()
        if xml_data:
            try:
                import xml.etree.ElementTree as ET

                # 检查 XML 中的 <!ENTITY 和 SYSTEM 定义
                entity_pattern = re.compile(r'<!ENTITY\s+\S+\s+SYSTEM\s+"([^"]+)"')
                system_files = entity_pattern.findall(xml_data)

                # 读取 SYSTEM 引用的文件内容（仅限白名单目录内，限制文件大小）
                file_contents = {}
                for filepath in system_files:
                    if not is_allowed_xml_path(filepath):
                        file_contents[filepath] = f"禁止读取文件（不在允许的目录范围内）"
                    else:
                        try:
                            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                                file_contents[filepath] = f.read(MAX_XML_FILE_READ)
                        except FileNotFoundError:
                            file_contents[filepath] = "文件不存在"
                        except PermissionError:
                            file_contents[filepath] = "无权限读取文件"
                        except Exception as e:
                            file_contents[filepath] = f"读取失败：{str(e)}"

                # 替换 XML 中的实体引用（先处理，再安全解析）
                for filepath, content in file_contents.items():
                    entity_match = re.search(r'<!ENTITY\s+(\S+)\s+SYSTEM\s+"' + re.escape(filepath) + r'"', xml_data)
                    if entity_match:
                        entity_name = entity_match.group(1)
                        xml_data = xml_data.replace(f"&{entity_name};", content)

                # 移除 DOCTYPE 声明，防止解析器接触外部实体
                xml_data = re.sub(r'<!DOCTYPE\s+\S+\s*\[.*?\]\s*>', '', xml_data, flags=re.DOTALL)
                xml_data = re.sub(r'<!DOCTYPE\s+\S+\s*>', '', xml_data)

                # 限制 XML 数据总大小（防止 Billion Laughs 内存耗尽）
                if len(xml_data) > 500000:
                    error = "XML 数据过大（超过 500KB）"
                    return render_template("xml_import.html", result=result, error=error)

                # 使用安全配置的解析器
                parser = ET.XMLParser()
                root = ET.fromstring(xml_data, parser=parser)

                users = []
                for user_elem in root.findall(".//user"):
                    name = user_elem.findtext("name", "")
                    email = user_elem.findtext("email", "")
                    users.append({"name": name, "email": email})

                result = json.dumps({"users": users, "files_read": system_files}, ensure_ascii=False, indent=2)

            except ET.ParseError as e:
                error = f"XML 解析错误：{str(e)}"
            except Exception as e:
                error = f"处理错误：{str(e)}"

    return render_template("xml_import.html", result=result, error=error)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
