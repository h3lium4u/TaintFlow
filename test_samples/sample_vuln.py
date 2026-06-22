# Sample vulnerable file for testing TaintFlow
import sqlite3
from flask import request

def get_user_data():
    # Source: request.args (CWE-89)
    username = request.args.get('username')
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection vulnerability (CWE-89)
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

def authenticate():
    # Hardcoded credential (CWE-798)
    api_token = "super_secret_token_12345678"
    print("Token initialized")
