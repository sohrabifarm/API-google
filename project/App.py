from flask import Flask, request, redirect, render_template, flash, url_for, session
import sqlite3
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
#app.secret_key = "MY_SUPER_SECRET_KEY_123"
#JWT_SECRET = "MY_JWT_SECRET_KEY_99"

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            user_type TEXT,
            province TEXT
        )
    """)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN user_type TEXT")
        cursor.execute("ALTER TABLE users ADD COLUMN province TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user_type = request.form.get("user_type")
        province = request.form.get("province")

        hashed_pass = generate_password_hash(password)
        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, password, user_type, province) VALUES (?,?,?,?)",
                (username, hashed_pass, user_type, province)
            )
            conn.commit()
            conn.close()
            flash("ثبت‌نام موفق! حالا وارد شوید.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("این نام کاربری قبلاً ثبت شده!")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["username"]
            session["role"] = user["user_type"]
            return redirect(url_for("dashboard"))
        
        flash("نام کاربری یا رمز عبور اشتباه است!")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"], role=session.get("role"))

@app.route("/admin/users")
def admin_users():
    if "user" not in session or session.get("role") != "admin":
        flash("فقط مدیران دسترسی دارند!")
        return redirect(url_for("dashboard"))
    
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, user_type, province FROM users").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")
        conn = get_db_connection()
        user = conn.execute("SELECT id FROM users WHERE username=?", (email,)).fetchone()
        conn.close()

        if user:
            token = jwt.encode({
                "reset_user_id": user["id"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            }, JWT_SECRET, algorithm="HS256")
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"\n لینک بازیابی: {reset_link}\n")
            flash("لینک بازیابی به کنسول ارسال شد.")
        else:
            flash("کاربر یافت نشد.")
    return render_template("forgot.html")

# تنظیمات گوگل (از کدهای قبلی خودتان)
GOOGLE_CLIENT_ID = "1067047072250-rhmbap0hhlhht70g9iaksqf7vt9g6omv.apps.googleusercontent.com"

@app.route("/google/login")
def google_login():
    # ایجاد لینک هدایت به صفحه گوگل
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        f"redirect_uri={url_for('google_callback', _external=True)}"
    )
    return redirect(google_auth_url)

@app.route("/google/callback")
def google_callback():
    # در اینجا باید کد دریافتی از گوگل با توکن تعویض شود
    # برای سادگی فعلاً فرض می‌کنیم کاربر تایید شده است
    # شما باید از کتابخانه google-auth استفاده کنید که قبلاً در کدهایتان بود
    flash("ورود با گوگل در این نسخه آزمایشی نیاز به تنظیم Client Secret دارد.")
    return redirect(url_for("login"))

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = data["reset_user_id"]
    except:
        flash("لینک نامعتبر یا منقضی شده.")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        new_pass = generate_password_hash(request.form.get("password"))
        conn = get_db_connection()
        conn.execute("UPDATE users SET password=? WHERE id=?", (new_pass, user_id))
        conn.commit()
        conn.close()
        flash("رمز با موفقیت تغییر کرد.")
        return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)