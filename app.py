from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask import Flask, render_template, request, session

app = Flask(__name__)

app.secret_key = "dev-secret-key"

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

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
        print("Email:", email)
        print("Password:", password)

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        
        conn.close()

        if user is None:
            print("User does not exist!")
        
        elif check_password_hash(user["password"], password):
            print("Login successful!")
            session["user_id"] = user["id"]

            print("Session:", session)
        
        else:
            print("Incorrect password")


    return render_template("login.html")

@app.route("/test-session")
def test_session():
    print("Session on test page:", session)
    return str(session.get("user_id"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)