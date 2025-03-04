import yaml
import bcrypt
import jwt
import datetime
import mysql.connector
from flask import Flask, request, jsonify

# Load configuration from YAML
with open("test.yaml", "r") as file:
    config = yaml.safe_load(file)

app = Flask(__name__)
app.config["SECRET_KEY"] = config["jwt_secret"]

# Connect to MySQL database
db = mysql.connector.connect(
    host=config["db"]["host"],
    user=config["db"]["user"],
    password=config["db"]["password"],
    database=config["db"]["database"]
)
cursor = db.cursor()

# Create tables if not exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_id VARCHAR(255) UNIQUE,
    expiry DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
""")
db.commit()

# Generate session ID
def generate_session_id(username):
    return f"{username}_{int(datetime.datetime.utcnow().timestamp())}"

# verify token
def verify_token():
    auth_header = request.headers.get("flask")
    token = auth_header.split()[1] if auth_header and "Bearer " in auth_header else None
    if not token:
        return None, jsonify({"message": "Token is missing!"}), 401
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_exp": False})
        cursor.execute("SELECT expiry FROM sessions WHERE session_id = %s", (data["session_id"],))
        session = cursor.fetchone()
        if not session:
            return None, jsonify({"message": "Session expired or invalid!"}), 401
        expiry_time = session[0]
        if datetime.datetime.utcnow() > expiry_time:
            cursor.execute("DELETE FROM sessions WHERE session_id = %s", (data["session_id"],))
            db.commit()
            return None, jsonify({"message": "Token has expired!"}), 401
        return data, None, 200
    except jwt.DecodeError:
        return None, jsonify({"message": "Token is invalid!"}), 401

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username, password = data["username"], data["password"]
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_pw))
        db.commit()
        return jsonify({"message": "User registered successfully!"})
    except mysql.connector.IntegrityError:
        return jsonify({"message": "User already exists!"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]
    cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user[1].encode("utf-8")):
        return jsonify({"message": "Invalid credentials!"}), 401
    
    user_id = user[0]
    cursor.execute("SELECT COUNT(*) FROM sessions WHERE user_id = %s", (user_id,))
    if cursor.fetchone()[0] >= 2:
        return jsonify({"message": "Too many devices logged in!"}), 403
    
    session_id = generate_session_id(username)
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    cursor.execute("INSERT INTO sessions (user_id, session_id, expiry) VALUES (%s, %s, %s)", (user_id, session_id, expiry_time))
    db.commit()
    
    token = jwt.encode({"user_id": user_id, "session_id": session_id, "exp": expiry_time}, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token, "expires_at": expiry_time.strftime("%Y-%m-%d %H:%M:%S UTC")})

@app.route("/logout", methods=["POST"])
def logout():
    auth_header = request.headers.get("flask")
    token = auth_header.split()[1] if auth_header and "Bearer " in auth_header else None
    if not token:
        return jsonify({"message": "Token is missing!"}), 401
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_exp": False})
        cursor.execute("DELETE FROM sessions WHERE session_id = %s", (data["session_id"],))
        db.commit()
        return jsonify({"message": "Logged out successfully!"})
    except jwt.DecodeError:
        return jsonify({"message": "Token is invalid!"}), 401

@app.route("/active_sessions", methods=["GET"])
def active_sessions():
    data, error_response, status = verify_token()
    if error_response:
        return error_response, status
    cursor.execute("SELECT session_id, expiry FROM sessions")
    sessions = cursor.fetchall()
    return jsonify({"sessions": [{"session_id": s[0], "expires_at": s[1].strftime("%Y-%m-%d %H:%M:%S UTC")} for s in sessions]})

# Cleanup expired sessions
def cleanup_sessions():
    cursor.execute("DELETE FROM sessions WHERE expiry < NOW()")
    db.commit()

if __name__ == "__main__":
    app.run(debug=True)
