import os
import uuid

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

from werkzeug.utils import secure_filename

from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask import Flask, render_template, request, session, redirect, flash, url_for
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


app.secret_key = os.environ.get("SECRET_KEY")

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

def add_profile_picture_column():
    conn = get_db_connection()

    columns = conn.execute("PRAGMA table_info(users)").fetchall()

    column_names = [column["name"] for column in columns]

    if "profile_picture" not in column_names:
        conn.execute(
            "ALTER TABLE users ADD COLUMN profile_picture TEXT"
        )
        conn.commit()

    conn.close()

add_profile_picture_column()

def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()



@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        print("Username:", username)
        print("Email:", email)
        
        if password != confirm_password:
            print("Passwords do not match!")
        else:
            password_hash = generate_password_hash(password)
            
            print("Password hash:", password_hash)
            
            conn = get_db_connection()
            
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )

            conn.commit()
            conn.close()

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user is None:
            flash("Incorrect email or password!")

        elif check_password_hash(user["password"], password):
            print("Login successful!")

            session["user_id"] = user["id"]

            print("Session:", session)

            return redirect("/dashboard")

        else:
            flash("Incorrect email or password")

    return render_template("login.html")



@app.route("/test-session")
def test_session():
    print("Session on test page:", session)
    return str(session.get("user_id"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    return render_template("dashboard.html", user=user)



@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        username = request.form["username"]
        profile_picture = request.files.get("profile_picture")

        conn = get_db_connection()

        conn.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            (username, session["user_id"])
        )

        if profile_picture and profile_picture.filename:
            if allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)

                extension = filename.rsplit(".", 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{extension}"

                profile_picture.save(
                    os.path.join(app.config["UPLOAD_FOLDER"], filename)
                )

                conn.execute(
                    "UPDATE users SET profile_picture = ? WHERE id = ?",
                    (filename, session["user_id"])
                )

                flash("Profile updated successfully.")
            else:
                flash("Only PNG, JPG, JPEG, and WEBP images are allowed.")

        conn.commit()
        conn.close()

        return redirect("/profile")

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    return render_template("profile.html", user=user)

@app.route("/change-password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")
    
    password = request.form["password"]
    confirm_password = request.form["password"]

    if password != "confirm_password":
        flash("Password does not match")
        return redirect("/profile")

    if password == "":
        flash("Password can not be empty, put a valid password!!")
        return redirect("/profile")

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()

    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
            (hashed_password, session["user_id"])
    )

    conn.commit()
    conn.close()

    return redirect("/profile")

@app.route("/login/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()

    user_info = token["userinfo"]

    email = user_info["email"]
    username = user_info["name"]

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if user is None:
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES(?, ?, ?)",
            (username, email, "")
        )

        conn.commit()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    
    conn.close()

    session["user_id"] = user["id"]

    return redirect("/dashboard")



@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect("/login")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)