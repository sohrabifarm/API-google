from flask import Flask, request, redirect, render_template, flash, jsonify
import sqlite3
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "SECRET_KEY"   # فقط برای flash
JWT_SECRET = "MY_JWT_SECRET"   # برای امضای توکن

# -----------------------------
# ایجاد دیتابیس و جدول‌ها
# -----------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


# ------------------------------------------------------
# صفحه ثبت‌نام
# ------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed_pass = generate_password_hash(password)

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?,?)",
                           (username, hashed_pass))
            conn.commit()
            conn.close()
        except:
            flash("این نام کاربری قبلاً ثبت شده!")
            return redirect("/register")

        flash("ثبت‌نام با موفقیت انجام شد! حالا وارد شوید.")
        return redirect("/login")

    return render_template("register.html")


# ------------------------------------------------------
# صفحه لاگین
# ------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash("کاربری با این نام وجود ندارد!")
            return redirect("/login")

        user_id, hashed_pass = user

        if not check_password_hash(hashed_pass, password):
            flash("رمز اشتباه است!")
            return redirect("/login")

        # ساخت JWT token
        token = jwt.encode({
            "user_id": user_id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }, JWT_SECRET, algorithm="HS256")

        flash(f"ورود موفق! توکن شما: {token}")
        return redirect("/login")

    return render_template("login.html")


# ------------------------------------------------------
# API حفاظت‌شده – فقط با توکن قابل دسترس است
# ------------------------------------------------------
@app.route("/protected", methods=["GET"])
def protected():

    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "توکن ارسال نشده"}), 401

    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({"message": "دسترسی موفق!", "data": data})
    except:
        return jsonify({"error": "توکن نامعتبر یا منقضی شده"}), 401


if __name__ == "__main__":
    app.run(debug=True)
