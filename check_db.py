import sqlite3

conn = sqlite3.connect("database.db")

users = conn.execute("SELECT * FROM users").fetchall()

print(users)

conn.close()