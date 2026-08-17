from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash
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

        # Check if email already exists
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

        # Hash the password before storing it
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


if __name__ == "__main__":
    app.run(debug=True)