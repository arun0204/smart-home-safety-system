from flask import Flask
from database import get_db_connection

app = Flask(__name__)


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


if __name__ == "__main__":
    app.run(debug=True)