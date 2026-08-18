from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return "Smart Home Safety System Backend is Running!"


@app.route("/test-db")
def test_db():
    try:
        connection = get_db_connection()

        if connection.is_connected():
            connection.close()
            return "MySQL Database Connected Successfully!"

    except Exception as e:
        return f"Database Connection Failed: {e}"


@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({
                "message": "Name, email and password are required"
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT user_id FROM users WHERE email = %s",
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            connection.close()

            return jsonify({
                "message": "Email already registered"
            }), 409

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users (name, email, password)
            VALUES (%s, %s, %s)
            """,
            (name, email, hashed_password)
        )

        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({
            "message": "User registered successfully"
        }), 201

    except Exception as e:
        return jsonify({
            "message": "Registration failed",
            "error": str(e)
        }), 500


@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({
                "message": "Email and password are required"
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT user_id, name, email, password, role
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if not user:
            return jsonify({
                "message": "Invalid email or password"
            }), 401

        if not check_password_hash(user["password"], password):
            return jsonify({
                "message": "Invalid email or password"
            }), 401

        return jsonify({
            "message": "Login successful",
            "user": {
                "user_id": user["user_id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
        }), 200

    except Exception as e:
        return jsonify({
            "message": "Login failed",
            "error": str(e)
        }), 500


@app.route("/door-status", methods=["GET"])
def door_status():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT event_id, event_type, status, user_id, timestamp
            FROM door_events
            ORDER BY timestamp DESC
            LIMIT 1
        """)

        event = cursor.fetchone()

        cursor.close()
        connection.close()

        if not event:
            return jsonify({
                "door_status": "LOCKED",
                "message": "No door events found"
            }), 200

        return jsonify({
            "door_status": event["status"],
            "event_type": event["event_type"],
            "user_id": event["user_id"],
            "timestamp": event["timestamp"].isoformat()
                if event["timestamp"] else None
        }), 200

    except Exception as e:
        return jsonify({
            "message": "Failed to get door status",
            "error": str(e)
        }), 500

@app.route("/door-control", methods=["POST"])
def door_control():

    try:

        data = request.get_json()

        action = data.get("action")

        if action not in ["LOCK", "UNLOCK"]:
            return jsonify({
                "message": "Invalid action"
            }), 400


        status = "LOCKED" if action == "LOCK" else "UNLOCKED"

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO door_events
            (event_type, status, user_id)
            VALUES (%s, %s, %s)
            """,
            ("DOOR_CONTROL", status, 2)
        )

        connection.commit()

        cursor.close()
        connection.close()


        return jsonify({
            "message": "Door " + status.lower(),
            "door_status": status
        }), 200


    except Exception as e:

        return jsonify({
            "message": "Door control failed",
            "error": str(e)
        }), 500
        
if __name__ == "__main__":
    app.run(debug=True)