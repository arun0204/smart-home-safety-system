from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db_connection

import urllib.request
import json
import os
import time
import shutil
import cv2
import numpy as np
import requests
import secrets
import re
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)


# =========================================================
# DOOR PIN SECURITY
# =========================================================

PIN_LENGTH = 6


# =========================================================
# PASSWORD RESET SECURITY
# =========================================================

def ensure_password_reset_table():
    """Create the password reset table if it does not exist."""
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                reset_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                code_hash VARCHAR(255) NOT NULL,
                expires_at DATETIME NOT NULL,
                used_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                CONSTRAINT fk_password_reset_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(user_id)
                    ON DELETE CASCADE
            )
            """
        )

        connection.commit()
        print("PASSWORD RESET TABLE READY")
        return True

    except Exception as e:
        print("PASSWORD RESET TABLE ERROR:", e)
        return False

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# Prepare the password reset table when Flask starts.
ensure_password_reset_table()


def ensure_door_pin_table():
    """Create the per-user door PIN table if it does not exist."""
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS door_pins (
                user_id INT NOT NULL PRIMARY KEY,
                pin_hash VARCHAR(255) NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_door_pins_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(user_id)
                    ON DELETE CASCADE
            )
            """
        )

        connection.commit()
        print("DOOR PIN TABLE READY")
        return True

    except Exception as e:
        print("DOOR PIN TABLE ERROR:", e)
        return False

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_user_password_hash(user_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT password FROM users WHERE user_id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        return user["password"] if user else None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_door_pin_hash(user_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT pin_hash FROM door_pins WHERE user_id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        return row["pin_hash"] if row else None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def valid_pin(pin):
    return (
        isinstance(pin, str)
        and len(pin) == PIN_LENGTH
        and pin.isdigit()
    )


# Prepare the PIN table when Flask starts.
ensure_door_pin_table()


# =========================================================
# FRONTEND PATH
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

FRONTEND_DIR = os.path.join(
    BASE_DIR,
    "frontend"
)


# =========================================================
# ESP32 CLOUD COMMUNICATION
# =========================================================
#
# The ESP32 is on the home/college Wi-Fi network and cannot be
# reached directly by the cloud server because it is normally
# behind NAT/private Wi-Fi.
#
# Therefore:
#   1. Flask stores LOCK/UNLOCK commands in MySQL.
#   2. ESP32 polls /esp32/commands over HTTPS.
#   3. ESP32 executes the command locally.
#   4. ESP32 reports the result to /esp32/command-result.
#   5. ESP32 periodically sends sensor/status data to /esp32/status.
#
# The browser never needs the ESP32's private IP address.
# =========================================================

ESP32_TOKEN = os.getenv("ESP32_TOKEN")
ESP32_CLOUD_MODE = True

ESP32_STATUS_ID = 1
ESP32_ONLINE_SECONDS = 20
ESP32_COMMAND_TIMEOUT_SECONDS = 10


def ensure_esp32_tables():
    """Create the cloud command queue and latest ESP32 status tables."""
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS esp32_commands (
                command_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                command VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                response TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                executed_at DATETIME NULL,
                INDEX idx_esp32_commands_status_created
                    (status, created_at)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS esp32_status (
                status_id TINYINT PRIMARY KEY,
                lock_status VARCHAR(20) DEFAULT 'UNKNOWN',
                door_status VARCHAR(20) DEFAULT 'UNKNOWN',
                temperature DOUBLE NULL,
                humidity DOUBLE NULL,
                gas DOUBLE NULL,
                motion VARCHAR(20) DEFAULT 'UNKNOWN',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            INSERT IGNORE INTO esp32_status
            (
                status_id,
                lock_status,
                door_status,
                motion
            )
            VALUES
            (%s, 'UNKNOWN', 'UNKNOWN', 'UNKNOWN')
            """,
            (ESP32_STATUS_ID,)
        )

        connection.commit()

        print("ESP32 CLOUD TABLES READY")
        return True

    except Exception as e:
        print("ESP32 CLOUD TABLE ERROR:", e)
        return False

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


ensure_esp32_tables()


def esp32_token_valid():
    """Validate the secret token used only by the physical ESP32."""
    if not ESP32_TOKEN:
        print("ESP32 TOKEN ERROR: ESP32_TOKEN is not configured.")
        return False

    supplied_token = request.headers.get("X-ESP32-Token")

    if not supplied_token:
        authorization = request.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            supplied_token = authorization[7:].strip()

    return secrets.compare_digest(
        str(supplied_token or ""),
        str(ESP32_TOKEN)
    )


def require_esp32_token():
    """Return an error response when a request is not from the ESP32."""
    if not esp32_token_valid():
        return jsonify({
            "success": False,
            "message": "ESP32 authentication failed"
        }), 401

    return None


def get_cached_esp32_status():
    """Read the latest status reported by the physical ESP32."""
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                status_id,
                lock_status,
                door_status,
                temperature,
                humidity,
                gas,
                motion,
                updated_at
            FROM esp32_status
            WHERE status_id = %s
            LIMIT 1
            """,
            (ESP32_STATUS_ID,)
        )

        row = cursor.fetchone()

        if not row:
            return {
                "online": False,
                "lock_status": "UNKNOWN",
                "door_status": "UNKNOWN",
                "temperature": None,
                "humidity": None,
                "gas": None,
                "motion": "UNKNOWN",
                "updated_at": None
            }

        updated_at = row.get("updated_at")

        online = False

        if updated_at:
            try:
                age_seconds = (
                    datetime.now() - updated_at
                ).total_seconds()

                online = (
                    age_seconds <= ESP32_ONLINE_SECONDS
                )
            except Exception:
                online = False

        return {
            "online": online,
            "lock_status": row.get("lock_status") or "UNKNOWN",
            "door_status": row.get("door_status") or "UNKNOWN",
            "temperature": row.get("temperature"),
            "humidity": row.get("humidity"),
            "gas": row.get("gas"),
            "motion": row.get("motion") or "UNKNOWN",
            "updated_at": (
                updated_at.isoformat()
                if updated_at
                else None
            )
        }

    except Exception as e:
        print("GET ESP32 STATUS ERROR:", e)

        return {
            "online": False,
            "lock_status": "UNKNOWN",
            "door_status": "UNKNOWN",
            "temperature": None,
            "humidity": None,
            "gas": None,
            "motion": "UNKNOWN",
            "updated_at": None,
            "error": str(e)
        }

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def queue_esp32_command(command):
    """Put a LOCK/UNLOCK command into the cloud MySQL queue."""
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO esp32_commands
            (
                command,
                status
            )
            VALUES
            (%s, 'PENDING')
            """,
            (command,)
        )

        connection.commit()

        command_id = cursor.lastrowid

        return command_id

    except Exception as e:
        print("QUEUE ESP32 COMMAND ERROR:", e)
        return None

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def wait_for_esp32_command(command_id, timeout_seconds=None):
    """
    Wait briefly for the ESP32 to execute a queued command.

    This keeps the existing browser behaviour synchronous while the
    actual ESP32 communication remains cloud-based.
    """
    if timeout_seconds is None:
        timeout_seconds = ESP32_COMMAND_TIMEOUT_SECONDS

    deadline = time.time() + timeout_seconds

    while time.time() < deadline:

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT
                    command_id,
                    command,
                    status,
                    response,
                    created_at,
                    executed_at
                FROM esp32_commands
                WHERE command_id = %s
                LIMIT 1
                """,
                (command_id,)
            )

            row = cursor.fetchone()

            if row and row["status"] in (
                "SUCCESS",
                "FAILED"
            ):
                return row

        except Exception as e:
            print(
                "WAIT FOR ESP32 COMMAND ERROR:",
                e
            )

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        time.sleep(0.5)

    return None


def send_esp32_command(endpoint):
    """
    Cloud replacement for the old private-IP ESP32 request.

    /status reads the latest cached status.
    /lock and /unlock create a cloud command and wait for the ESP32
    to report the result.
    """
    if endpoint == "/status":
        status = get_cached_esp32_status()

        if not status.get("updated_at"):
            return None

        return json.dumps({
            "lock_status": status.get(
                "lock_status",
                "UNKNOWN"
            ),
            "door_status": status.get(
                "door_status",
                "UNKNOWN"
            ),
            "temperature": status.get(
                "temperature"
            ),
            "humidity": status.get(
                "humidity"
            ),
            "gas": status.get(
                "gas"
            ),
            "motion": status.get(
                "motion",
                "UNKNOWN"
            ),
            "updated_at": status.get(
                "updated_at"
            )
        })

    command_map = {
        "/lock": "LOCK",
        "/unlock": "UNLOCK"
    }

    command = command_map.get(endpoint)

    if command is None:
        print(
            "UNKNOWN ESP32 CLOUD ENDPOINT:",
            endpoint
        )
        return None

    command_id = queue_esp32_command(command)

    if command_id is None:
        return None

    print("ESP32 CLOUD COMMAND QUEUED")
    print("Command ID:", command_id)
    print("Command:", command)

    result = wait_for_esp32_command(
        command_id
    )

    if not result:
        print(
            "ESP32 CLOUD COMMAND TIMEOUT:",
            command_id
        )
        return None

    response = (
        result.get("response")
        or ""
    )

    if result.get("status") == "SUCCESS":
        return response or (
            "LOCKED"
            if command == "LOCK"
            else "UNLOCKED"
        )

    print(
        "ESP32 CLOUD COMMAND FAILED:",
        result
    )

    return None


# =========================================================
# ESP32 DEVICE POLLING ENDPOINT
# =========================================================

@app.route(
    "/esp32/commands",
    methods=["GET"]
)
def esp32_commands():

    auth_error = require_esp32_token()

    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                command_id,
                command,
                created_at
            FROM esp32_commands
            WHERE status = 'PENDING'
            ORDER BY created_at ASC
            LIMIT 1
            """
        )

        command = cursor.fetchone()

        if not command:
            return jsonify({
                "success": True,
                "command": None
            }), 200

        return jsonify({
            "success": True,
            "command": {
                "command_id": command["command_id"],
                "command": command["command"],
                "created_at": (
                    command["created_at"].isoformat()
                    if command["created_at"]
                    else None
                )
            }
        }), 200

    except Exception as e:

        print(
            "ESP32 COMMAND POLL ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": "Failed to get ESP32 commands",
            "error": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# ESP32 COMMAND RESULT ENDPOINT
# =========================================================

@app.route(
    "/esp32/command-result",
    methods=["POST"]
)
def esp32_command_result():

    auth_error = require_esp32_token()

    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:

        data = request.get_json() or {}

        command_id = data.get("command_id")
        command_status = str(
            data.get("status") or ""
        ).upper()
        response_text = str(
            data.get("response") or ""
        )

        try:
            command_id = int(command_id)
        except (ValueError, TypeError):
            return jsonify({
                "success": False,
                "message": "Valid command_id is required"
            }), 400

        if command_status not in (
            "SUCCESS",
            "FAILED"
        ):
            return jsonify({
                "success": False,
                "message": (
                    "status must be SUCCESS or FAILED"
                )
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE esp32_commands
            SET
                status = %s,
                response = %s,
                executed_at = NOW()
            WHERE command_id = %s
              AND status = 'PENDING'
            """,
            (
                command_status,
                response_text,
                command_id
            )
        )

        connection.commit()

        if cursor.rowcount == 0:
            return jsonify({
                "success": False,
                "message": "Command not found or already completed"
            }), 404

        print("ESP32 COMMAND RESULT")
        print("Command ID:", command_id)
        print("Status:", command_status)
        print("Response:", response_text)

        return jsonify({
            "success": True,
            "message": "Command result saved"
        }), 200

    except Exception as e:

        if connection:
            connection.rollback()

        print(
            "ESP32 COMMAND RESULT ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": "Failed to save command result",
            "error": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# ESP32 STATUS UPDATE ENDPOINT
# =========================================================

@app.route(
    "/esp32/status",
    methods=["POST"]
)
def esp32_status_update():

    auth_error = require_esp32_token()

    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:

        data = request.get_json() or {}

        lock_status = str(
            data.get("lock_status", "UNKNOWN")
        ).upper()

        door_status = str(
            data.get("door_status", "UNKNOWN")
        ).upper()

        temperature = data.get("temperature")
        humidity = data.get("humidity")
        gas = data.get("gas")
        motion = str(
            data.get("motion", "UNKNOWN")
        ).upper()

        allowed_lock_statuses = {
            "LOCKED",
            "UNLOCKED",
            "UNKNOWN"
        }

        allowed_door_statuses = {
            "OPEN",
            "CLOSED",
            "UNKNOWN"
        }

        if lock_status not in allowed_lock_statuses:
            lock_status = "UNKNOWN"

        if door_status not in allowed_door_statuses:
            door_status = "UNKNOWN"

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO esp32_status
            (
                status_id,
                lock_status,
                door_status,
                temperature,
                humidity,
                gas,
                motion
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            ON DUPLICATE KEY UPDATE
                lock_status = VALUES(lock_status),
                door_status = VALUES(door_status),
                temperature = VALUES(temperature),
                humidity = VALUES(humidity),
                gas = VALUES(gas),
                motion = VALUES(motion),
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                ESP32_STATUS_ID,
                lock_status,
                door_status,
                temperature,
                humidity,
                gas,
                motion
            )
        )

        connection.commit()

        cursor.close()
        cursor = None
        connection.close()
        connection = None

        # Process gas alerts after the status has been stored.
        gas_status = process_gas_status(
            gas
        )

        return jsonify({
            "success": True,
            "message": "ESP32 status received",
            "lock_status": lock_status,
            "door_status": door_status,
            "gas_status": gas_status
        }), 200

    except Exception as e:

        if connection:
            connection.rollback()

        print(
            "ESP32 STATUS UPDATE ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": "Failed to save ESP32 status",
            "error": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# ESP32 STATUS UPDATE - OPTIONAL GET FOR DEVICE TESTING
# =========================================================

@app.route(
    "/esp32/status",
    methods=["GET"]
)
def esp32_status_device_get():

    auth_error = require_esp32_token()

    if auth_error:
        return auth_error

    return jsonify({
        "success": True,
        "status": get_cached_esp32_status()
    }), 200


# =========================================================
# GAS THRESHOLD
# =========================================================

GAS_THRESHOLD = 750


# =========================================================
# GET FAMILY MEMBERS FOR A FAMILY OWNER
# =========================================================

@app.route(
    "/family-members",
    methods=["GET"]
)
def get_family_members():

    try:

        owner_user_id = request.args.get(
            "owner_user_id",
            type=int
        )

        if owner_user_id is None:

            return jsonify({
                "message":
                    "owner_user_id is required"
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # Make sure the requested user is a family owner.
        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                family_owner_id
            FROM users
            WHERE user_id = %s
              AND family_owner_id IS NULL
            LIMIT 1
            """,
            (owner_user_id,)
        )

        owner = cursor.fetchone()

        if not owner:

            cursor.close()
            connection.close()

            return jsonify({
                "message":
                    "Family owner not found"
            }), 404

        # Return only members belonging to this family owner.
        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                family_owner_id
            FROM users
            WHERE family_owner_id = %s
            ORDER BY user_id
            """,
            (owner_user_id,)
        )

        family_members = cursor.fetchall()

        cursor.close()
        connection.close()

        return jsonify({
            "owner": owner,
            "family_members":
                family_members,
            "count":
                len(family_members)
        }), 200

    except Exception as e:

        print(
            "GET FAMILY MEMBERS ERROR:",
            e
        )

        return jsonify({

            "message":
                "Failed to get family members",

            "error":
                str(e)

        }), 500


# =========================================================
# FACE VERIFICATION STATUS
# =========================================================

face_verification_enabled = True


# =========================================================
# FACE RECOGNITION FILES
# =========================================================

TRAINER_PATH = "/Users/Arun/Desktop/trainer.yml"

CASCADE_PATH = (
    "/Users/Arun/Desktop/"
    "haarcascade_frontalface_default.xml"
)

FACES_DIR = "/Users/Arun/Desktop/faces"


# =========================================================
# CREATE GAS ALERT
# =========================================================

def create_gas_alert_if_needed(gas_value):

    try:

        if gas_value is None:
            return False

        gas_value = float(gas_value)

        if gas_value < GAS_THRESHOLD:
            return False

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT alert_id
            FROM alerts
            WHERE alert_type = 'GAS_SMOKE'
            AND status = 'ACTIVE'
            LIMIT 1
            """
        )

        existing_alert = cursor.fetchone()

        if existing_alert:

            cursor.close()
            connection.close()

            print(
                "GAS ALERT ALREADY ACTIVE"
            )

            return False

        cursor.execute(
            """
            INSERT INTO alerts
            (
                alert_type,
                severity,
                message,
                status,
                user_id
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                "GAS_SMOKE",
                "HIGH",
                (
                    "Gas or smoke detected. "
                    f"Gas value: {int(gas_value)}"
                ),
                "ACTIVE",
                2
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        print(
            "================================="
        )

        print(
            "GAS ALERT CREATED"
        )

        print(
            "Gas Value:",
            gas_value
        )

        print(
            "================================="
        )

        return True

    except Exception as e:

        print(
            "GAS ALERT ERROR:",
            e
        )

        return False


# =========================================================
# RESOLVE GAS ALERT
# =========================================================

def resolve_gas_alert_if_normal(gas_value):

    try:

        if gas_value is None:
            return False

        gas_value = float(gas_value)

        if gas_value >= GAS_THRESHOLD:
            return False

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET status = 'RESOLVED'
            WHERE alert_type = 'GAS_SMOKE'
            AND status = 'ACTIVE'
            """
        )

        affected_rows = cursor.rowcount

        connection.commit()

        cursor.close()
        connection.close()

        if affected_rows > 0:

            print(
                "================================="
            )

            print(
                "GAS ALERT RESOLVED"
            )

            print(
                "Gas Value:",
                gas_value
            )

            print(
                "================================="
            )

            return True

        return False

    except Exception as e:

        print(
            "GAS ALERT RESOLVE ERROR:",
            e
        )

        return False


# =========================================================
# PROCESS GAS STATUS
# =========================================================

def process_gas_status(gas_value):

    if gas_value is None:
        return "UNKNOWN"

    try:

        gas_value = float(
            gas_value
        )

    except Exception:

        return "UNKNOWN"

    if gas_value >= GAS_THRESHOLD:

        create_gas_alert_if_needed(
            gas_value
        )

        return "DANGER"

    else:

        resolve_gas_alert_if_normal(
            gas_value
        )

        return "NORMAL"


# =========================================================
# FACE MODEL RETRAINING
# =========================================================

def retrain_face_model():

    try:

        print(
            "================================="
        )

        print(
            "RETRAINING FACE MODEL"
        )

        print(
            "================================="
        )

        if not os.path.exists(
            FACES_DIR
        ):

            print(
                "Faces directory does not exist."
            )

            return False

        face_cascade = (
            cv2.CascadeClassifier(
                CASCADE_PATH
            )
        )

        if face_cascade.empty():

            print(
                "ERROR: Haarcascade could not be loaded."
            )

            return False

        faces = []
        ids = []

        user_directories = sorted(
            os.listdir(
                FACES_DIR
            )
        )

        for directory_name in user_directories:

            directory_path = os.path.join(
                FACES_DIR,
                directory_name
            )

            if not os.path.isdir(
                directory_path
            ):
                continue

            if not directory_name.startswith(
                "user_"
            ):
                continue

            try:

                user_id = int(
                    directory_name.replace(
                        "user_",
                        ""
                    )
                )

            except ValueError:

                continue

            image_files = sorted(
                os.listdir(
                    directory_path
                )
            )

            for image_name in image_files:

                image_path = os.path.join(
                    directory_path,
                    image_name
                )

                if not image_name.lower().endswith(
                    (
                        ".jpg",
                        ".jpeg",
                        ".png",
                        ".pgm"
                    )
                ):
                    continue

                image = cv2.imread(
                    image_path,
                    cv2.IMREAD_GRAYSCALE
                )

                if image is None:
                    continue

                detected_faces = (
                    face_cascade.detectMultiScale(
                        image,
                        scaleFactor=1.3,
                        minNeighbors=5
                    )
                )

                if len(detected_faces) > 0:

                    for (
                        x,
                        y,
                        w,
                        h
                    ) in detected_faces:

                        face_image = image[
                            y:y + h,
                            x:x + w
                        ]

                        faces.append(
                            face_image
                        )

                        ids.append(
                            user_id
                        )

                else:

                    # Some existing training images may already
                    # contain only the cropped face.
                    faces.append(
                        image
                    )

                    ids.append(
                        user_id
                    )

        if len(faces) == 0:

            print(
                "No registered face samples remain."
            )

            # No valid model can be trained with zero faces.
            if os.path.exists(
                TRAINER_PATH
            ):

                os.remove(
                    TRAINER_PATH
                )

                print(
                    "Old trainer.yml removed."
                )

            return True

        recognizer = (
            cv2.face.LBPHFaceRecognizer_create()
        )

        recognizer.train(
            faces,
            np.array(ids)
        )

        recognizer.write(
            TRAINER_PATH
        )

        print(
            "Face model retrained successfully."
        )

        print(
            "Total samples:",
            len(faces)
        )

        print(
            "User IDs:",
            sorted(set(ids))
        )

        print(
            "Trainer:",
            TRAINER_PATH
        )

        print(
            "================================="
        )

        return True

    except Exception as e:

        print(
            "FACE MODEL RETRAIN ERROR:",
            e
        )

        return False


# =========================================================
# DELETE USER ACCOUNT
# =========================================================

@app.route(
    "/delete-user/<int:user_id>",
    methods=["DELETE"]
)
def delete_user_account(user_id):

    connection = None
    cursor = None

    try:

        # -------------------------------------------------
        # SECURITY INPUT
        #
        # Deleting a family-member account requires the
        # family owner's current account password.
        # The password is checked here in Flask, not only
        # in the browser.
        # -------------------------------------------------

        data = request.get_json(silent=True) or {}

        owner_user_id = data.get("owner_user_id")
        account_password = data.get("account_password")

        try:
            owner_user_id = int(owner_user_id)
        except (ValueError, TypeError):
            return jsonify({
                "deleted": False,
                "message": "Valid family owner ID is required"
            }), 400

        if not isinstance(account_password, str) or not account_password:
            return jsonify({
                "deleted": False,
                "message": "Family owner's account password is required"
            }), 401

        if owner_user_id == user_id:
            return jsonify({
                "deleted": False,
                "message": "The family owner cannot delete their own account here"
            }), 403

        # -------------------------------------------------
        # CHECK TARGET USER AND FAMILY OWNER
        # -------------------------------------------------

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                family_owner_id
            FROM users
            WHERE user_id = %s
            LIMIT 1
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            return jsonify({
                "deleted": False,
                "message": "User not found"
            }), 404

        # Only family members can be deleted through this
        # family-owner protected endpoint.
        if user["family_owner_id"] is None:
            return jsonify({
                "deleted": False,
                "message": (
                    "The family owner account cannot be deleted "
                    "from this action."
                )
            }), 403

        # The selected user must actually belong to the
        # authenticated family owner's family.
        if int(user["family_owner_id"]) != owner_user_id:
            return jsonify({
                "deleted": False,
                "message": (
                    "You are not authorized to delete this user."
                )
            }), 403

        # -------------------------------------------------
        # VERIFY FAMILY OWNER
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                password,
                role,
                family_owner_id
            FROM users
            WHERE user_id = %s
            LIMIT 1
            """,
            (owner_user_id,)
        )

        owner = cursor.fetchone()

        if not owner:
            return jsonify({
                "deleted": False,
                "message": "Family owner account was not found"
            }), 404

        # Owner must be a root account.
        if owner["family_owner_id"] is not None:
            return jsonify({
                "deleted": False,
                "message": (
                    "Only the family owner can delete family members."
                )
            }), 403

        # -------------------------------------------------
        # VERIFY CURRENT ACCOUNT PASSWORD
        # -------------------------------------------------

        if not check_password_hash(
            owner["password"],
            account_password
        ):
            return jsonify({
                "deleted": False,
                "message": "Family owner's account password is incorrect"
            }), 401

        # -------------------------------------------------
        # FACE DIRECTORY
        # -------------------------------------------------

        user_face_directory = os.path.join(
            FACES_DIR,
            f"user_{user_id}"
        )

        face_directory_existed = os.path.isdir(
            user_face_directory
        )

        # -------------------------------------------------
        # DELETE DATABASE USER
        #
        # door_pins and password_reset_tokens use
        # ON DELETE CASCADE in the current schema.
        # -------------------------------------------------

        cursor.execute(
            """
            DELETE FROM users
            WHERE user_id = %s
              AND family_owner_id = %s
            """,
            (user_id, owner_user_id)
        )

        if cursor.rowcount != 1:
            connection.rollback()

            return jsonify({
                "deleted": False,
                "message": "User could not be deleted"
            }), 500

        connection.commit()

        # Close the database connection before filesystem/model work.
        cursor.close()
        cursor = None
        connection.close()
        connection = None

        # -------------------------------------------------
        # DELETE FACE DIRECTORY
        # -------------------------------------------------

        if face_directory_existed:

            shutil.rmtree(
                user_face_directory,
                ignore_errors=True
            )

            print(
                "USER FACE DIRECTORY DELETED:",
                user_face_directory
            )

        # -------------------------------------------------
        # RETRAIN FACE MODEL
        # -------------------------------------------------

        retrain_success = retrain_face_model()

        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        print("=================================")
        print("PROTECTED USER ACCOUNT DELETED")
        print("Family Owner ID:", owner_user_id)
        print("Family Owner:", owner["name"])
        print("Deleted User ID:", user_id)
        print("Deleted User:", user["name"])
        print("Face directory existed:", face_directory_existed)
        print("Face model retrained:", retrain_success)
        print("=================================")

        if retrain_success:

            message = (
                "User account and face data deleted successfully."
            )

        else:

            message = (
                "User account and face data were deleted, "
                "but the face model could not be retrained."
            )

        return jsonify({
            "deleted": True,
            "message": message,
            "user_id": user["user_id"],
            "name": user["name"],
            "face_deleted": face_directory_existed,
            "model_retrained": retrain_success
        }), 200

    except Exception as e:

        if connection:
            connection.rollback()

        print(
            "DELETE USER ERROR:",
            e
        )

        return jsonify({
            "deleted": False,
            "message": "User deletion failed",
            "error": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# FRONTEND PAGES
# =========================================================

@app.route("/")
def home():

    return send_from_directory(
        FRONTEND_DIR,
        "login.html"
    )


@app.route("/login.html")
def login_page():

    return send_from_directory(
        FRONTEND_DIR,
        "login.html"
    )


@app.route("/register.html")
def register_page():

    return send_from_directory(
        FRONTEND_DIR,
        "register.html"
    )

@app.route("/forgot-password.html")
def forgot_password_page():

    return send_from_directory(
        FRONTEND_DIR,
        "forgot-password.html"
    )

@app.route("/dashboard")
def dashboard():

    return send_from_directory(
        FRONTEND_DIR,
        "dashboard.html"
    )


@app.route("/dashboard.html")
def dashboard_html():

    return send_from_directory(
        FRONTEND_DIR,
        "dashboard.html"
    )


@app.route("/sensors.html")
def sensors_page():

    return send_from_directory(
        FRONTEND_DIR,
        "sensors.html"
    )


@app.route("/door-access.html")
def door_access_page():

    return send_from_directory(
        FRONTEND_DIR,
        "door-access.html"
    )


@app.route("/image-verification.html")
def image_verification_page():

    return send_from_directory(
        FRONTEND_DIR,
        "image-verification.html"
    )


@app.route("/alerts.html")
def alerts_page():

    return send_from_directory(
        FRONTEND_DIR,
        "alerts.html"
    )


@app.route("/access-logs.html")
def access_logs_page():

    return send_from_directory(
        FRONTEND_DIR,
        "access-logs.html"
    )


# =========================================================
# TEST DATABASE
# =========================================================

@app.route("/test-db")
def test_db():

    try:

        connection = get_db_connection()

        if connection.is_connected():

            connection.close()

            return (
                "MySQL Database "
                "Connected Successfully!"
            )

        connection.close()

        return "Database connection failed."

    except Exception as e:

        return (
            f"Database Connection Failed: {e}"
        )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    try:

        data = request.get_json() or {}

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if (
            not name
            or not email
            or not password
        ):

            return jsonify({
                "message":
                    "Name, email and password are required"
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            cursor.close()
            connection.close()

            return jsonify({
                "message":
                    "Email already registered"
            }), 409

        hashed_password = (
            generate_password_hash(password)
        )

        cursor.execute(
            """
            INSERT INTO users
            (name, email, password)
            VALUES (%s, %s, %s)
            """,
            (
                name,
                email,
                hashed_password
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({
            "message":
                "User registered successfully"
        }), 201

    except Exception as e:

        return jsonify({
            "message":
                "Registration failed",
            "error":
                str(e)
        }), 500



# =========================================================
# CREATE USER FOR FACE REGISTRATION
# =========================================================

@app.route(
    "/create-face-user",
    methods=["POST"]
)
def create_face_user():

    connection = None
    cursor = None

    try:

        data = request.get_json() or {}

        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        owner_user_id = data.get("owner_user_id")

        if owner_user_id is None:
            return jsonify({
                "message": "Family owner ID is required"
            }), 400

        try:
            owner_user_id = int(owner_user_id)
        except (ValueError, TypeError):
            return jsonify({
                "message": "Invalid family owner ID"
            }), 400

        if not name:
            return jsonify({
                "message": "Name is required"
            }), 400

        if not email:
            return jsonify({
                "message": "Email is required"
            }), 400

        if len(password) < 6:
            return jsonify({
                "message": "Password must be at least 6 characters"
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                family_owner_id
            FROM users
            WHERE user_id = %s
            """,
            (owner_user_id,)
        )

        owner = cursor.fetchone()

        if not owner:
            return jsonify({
                "message": "Family owner account was not found"
            }), 404

        # Only a root account (family_owner_id = NULL)
        # can add family members.
        if owner["family_owner_id"] is not None:
            return jsonify({
                "message": "Only the family owner can add family members"
            }), 403

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email
            FROM users
            WHERE LOWER(email) = %s
            """,
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({
                "message": "Email already registered",
                "user_id": existing_user["user_id"],
                "name": existing_user["name"],
                "email": existing_user["email"]
            }), 409

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password,
                role,
                family_owner_id
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                name,
                email,
                hashed_password,
                "user",
                owner_user_id
            )
        )

        connection.commit()

        new_user_id = cursor.lastrowid

        print("=================================")
        print("FAMILY MEMBER CREATED")
        print("Family Owner ID:", owner_user_id)
        print("Family Owner:", owner["name"])
        print("Member User ID:", new_user_id)
        print("Member Name:", name)
        print("Member Email:", email)
        print("=================================")

        return jsonify({
            "message": "Family member created successfully",
            "user": {
                "user_id": new_user_id,
                "name": name,
                "email": email,
                "role": "user",
                "family_owner_id": owner_user_id
            }
        }), 201

    except Exception as e:

        if connection:
            connection.rollback()

        print("CREATE FAMILY MEMBER ERROR:", e)

        return jsonify({
            "message": "Failed to create family member",
            "error": str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# REGISTER FACE IMAGES
# =========================================================

@app.route(
    "/register-face-images",
    methods=["POST"]
)
def register_face_images():

    try:

        # -------------------------------------------------
        # GET USER ID
        # -------------------------------------------------

        user_id = request.form.get("user_id")

        if user_id is None:

            return jsonify({
                "registered": False,
                "message": "User ID is required"
            }), 400

        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({
                "registered": False,
                "message": "Invalid User ID"
            }), 400

        # -------------------------------------------------
        # CHECK USER
        # -------------------------------------------------

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if not user:
            return jsonify({
                "registered": False,
                "message": "User not found"
            }), 404

        # -------------------------------------------------
        # CHECK FACE RECOGNITION SUPPORT
        # -------------------------------------------------

        if not hasattr(cv2, "face"):
            return jsonify({
                "registered": False,
                "message": (
                    "OpenCV face recognition module is not available"
                )
            }), 500

        # -------------------------------------------------
        # CHECK HAAR CASCADE
        # -------------------------------------------------

        if not os.path.exists(CASCADE_PATH):
            return jsonify({
                "registered": False,
                "message": "Haar cascade file not found"
            }), 500

        face_cascade = cv2.CascadeClassifier(CASCADE_PATH)

        if face_cascade.empty():
            return jsonify({
                "registered": False,
                "message": "Haar cascade could not be loaded"
            }), 500

        # -------------------------------------------------
        # GET CAPTURED IMAGES
        # -------------------------------------------------

        image_files = request.files.getlist("images")

        if not image_files:
            # Also accept a single file named "image".
            single_image = request.files.get("image")
            if single_image is not None:
                image_files = [single_image]

        if not image_files:
            return jsonify({
                "registered": False,
                "message": "At least one face image is required"
            }), 400

        # -------------------------------------------------
        # FACE DIRECTORY
        # -------------------------------------------------

        os.makedirs(FACES_DIR, exist_ok=True)

        user_face_directory = os.path.join(
            FACES_DIR,
            f"user_{user_id}"
        )

        # This endpoint is intended for a new face registration.
        # Do not silently overwrite an existing face registration.
        if os.path.isdir(user_face_directory):

            existing_files = [
                name for name in os.listdir(user_face_directory)
                if name.lower().endswith(
                    (".jpg", ".jpeg", ".png", ".pgm")
                )
            ]

            if existing_files:
                return jsonify({
                    "registered": False,
                    "message": (
                        "This user already has registered face data. "
                        "Delete the existing face first."
                    )
                }), 409

        os.makedirs(user_face_directory, exist_ok=True)

        # -------------------------------------------------
        # SAVE ONLY VALID FACE IMAGES
        # -------------------------------------------------

        saved_count = 0
        rejected_count = 0

        for index, image_file in enumerate(image_files, start=1):

            image_bytes = image_file.read()

            if not image_bytes:
                rejected_count += 1
                continue

            image_array = np.frombuffer(
                image_bytes,
                dtype=np.uint8
            )

            frame = cv2.imdecode(
                image_array,
                cv2.IMREAD_COLOR
            )

            if frame is None:
                rejected_count += 1
                continue

            gray = cv2.cvtColor(
                frame,
                cv2.COLOR_BGR2GRAY
            )

            detected_faces = face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.3,
                minNeighbors=5
            )

            # Registration accepts an image only when exactly one
            # face is visible. This avoids training the model with
            # unrelated people in the same frame.
            if len(detected_faces) != 1:
                rejected_count += 1
                continue

            file_name = f"face_{saved_count + 1:03d}.jpg"
            file_path = os.path.join(
                user_face_directory,
                file_name
            )

            # Save the original webcam image. retrain_face_model()
            # will detect and crop the face during training.
            with open(file_path, "wb") as output_file:
                output_file.write(image_bytes)

            saved_count += 1

        # -------------------------------------------------
        # REQUIRE ENOUGH VALID SAMPLES
        # -------------------------------------------------

        if saved_count < 5:

            shutil.rmtree(
                user_face_directory,
                ignore_errors=True
            )

            return jsonify({
                "registered": False,
                "message": (
                    "Not enough valid face images. "
                    "Please capture the face again."
                ),
                "saved_images": saved_count,
                "rejected_images": rejected_count
            }), 400

        # -------------------------------------------------
        # RETRAIN MODEL
        # -------------------------------------------------

        retrain_success = retrain_face_model()

        if not retrain_success:

            # Do not leave a partial registration if training fails.
            shutil.rmtree(
                user_face_directory,
                ignore_errors=True
            )

            # Restore the previous model from the remaining users.
            retrain_face_model()

            return jsonify({
                "registered": False,
                "message": "Face model could not be trained"
            }), 500

        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        print("=================================")
        print("FACE REGISTRATION SUCCESSFUL")
        print("User ID:", user_id)
        print("Name:", user["name"])
        print("Email:", user["email"])
        print("Saved images:", saved_count)
        print("Rejected images:", rejected_count)
        print("=================================")

        return jsonify({
            "registered": True,
            "message": "Face registered successfully",
            "user": {
                "user_id": user["user_id"],
                "name": user["name"],
                "email": user["email"]
            },
            "saved_images": saved_count,
            "rejected_images": rejected_count
        }), 200

    except Exception as e:

        print(
            "REGISTER FACE IMAGES ERROR:",
            e
        )

        return jsonify({
            "registered": False,
            "message": "Face registration failed",
            "error": str(e)
        }), 500


# =========================================================
# PASSWORD RESET - REQUEST RESET CODE
# =========================================================

@app.route(
    "/forgot-password/request",
    methods=["POST"]
)
def request_password_reset():

    try:

        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()

        if not email:
            return jsonify({
                "success": False,
                "message": "Email is required"
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email
            FROM users
            WHERE LOWER(email) = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        # Always return the same response for unknown emails.
        # This avoids revealing whether an account exists.
        if not user:
            cursor.close()
            connection.close()

            return jsonify({
                "success": True,
                "message": (
                    "If that email is registered, a reset code "
                    "has been generated."
                )
            }), 200

        # Invalidate any previous unused reset codes for this user.
        cursor.execute(
            """
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE user_id = %s
            AND used_at IS NULL
            """,
            (user["user_id"],)
        )

        # Generate a 6-digit one-time code.
        reset_code = f"{secrets.randbelow(1000000):06d}"

        # Store only a hash of the reset code.
        code_hash = generate_password_hash(reset_code)

        expires_at = datetime.now() + timedelta(minutes=10)

        cursor.execute(
            """
            INSERT INTO password_reset_tokens
            (
                user_id,
                code_hash,
                expires_at
            )
            VALUES
            (
                %s,
                %s,
                %s
            )
            """,
            (
                user["user_id"],
                code_hash,
                expires_at
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        # DEVELOPMENT ONLY:
        # Until email delivery is configured, print the code in the
        # Flask terminal instead of exposing it through the API.
        print("=================================")
        print("PASSWORD RESET CODE")
        print("User ID:", user["user_id"])
        print("Email:", user["email"])
        print("Code:", reset_code)
        print("Expires:", expires_at.strftime("%Y-%m-%d %H:%M:%S"))
        print("=================================")

        return jsonify({
            "success": True,
            "message": (
                "If that email is registered, a reset code "
                "has been generated."
            ),
            "development_mode": True
        }), 200

    except Exception as e:

        print(
            "PASSWORD RESET REQUEST ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": "Failed to create password reset request",
            "error": str(e)
        }), 500


# =========================================================
# PASSWORD RESET - VERIFY CODE AND CHANGE PASSWORD
# =========================================================

@app.route(
    "/forgot-password/reset",
    methods=["POST"]
)
def reset_forgotten_password():

    try:

        data = request.get_json() or {}

        email = (data.get("email") or "").strip().lower()
        reset_code = str(data.get("code") or "").strip()
        new_password = data.get("new_password") or ""

        if not email or not reset_code or not new_password:
            return jsonify({
                "success": False,
                "message": (
                    "Email, reset code and new password are required"
                )
            }), 400

        if not re.fullmatch(r"\d{6}", reset_code):
            return jsonify({
                "success": False,
                "message": "Reset code must be exactly 6 digits"
            }), 400

        if len(new_password) < 6:
            return jsonify({
                "success": False,
                "message": "Password must be at least 6 characters"
            }), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                password
            FROM users
            WHERE LOWER(email) = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        if not user:
            cursor.close()
            connection.close()

            return jsonify({
                "success": False,
                "message": "Invalid email or reset code"
            }), 400

        # Find the newest unused reset code for this user.
        cursor.execute(
            """
            SELECT
                reset_id,
                code_hash,
                expires_at
            FROM password_reset_tokens
            WHERE user_id = %s
            AND used_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user["user_id"],)
        )

        reset_record = cursor.fetchone()

        if not reset_record:
            cursor.close()
            connection.close()

            return jsonify({
                "success": False,
                "message": "Invalid or expired reset code"
            }), 400

        # Check expiry.
        if datetime.now() > reset_record["expires_at"]:
            cursor.execute(
                """
                UPDATE password_reset_tokens
                SET used_at = NOW()
                WHERE reset_id = %s
                """,
                (reset_record["reset_id"],)
            )

            connection.commit()
            cursor.close()
            connection.close()

            return jsonify({
                "success": False,
                "message": "Reset code has expired"
            }), 400

        # Verify the submitted code against the stored hash.
        if not check_password_hash(
            reset_record["code_hash"],
            reset_code
        ):
            cursor.close()
            connection.close()

            return jsonify({
                "success": False,
                "message": "Invalid or expired reset code"
            }), 400

        # Update the account password with a secure hash.
        new_password_hash = generate_password_hash(
            new_password
        )

        cursor.execute(
            """
            UPDATE users
            SET password = %s
            WHERE user_id = %s
            """,
            (
                new_password_hash,
                user["user_id"]
            )
        )

        # Mark the reset code as used so it cannot be reused.
        cursor.execute(
            """
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE reset_id = %s
            """,
            (reset_record["reset_id"],)
        )

        connection.commit()

        cursor.close()
        connection.close()

        print("=================================")
        print("PASSWORD RESET SUCCESSFUL")
        print("User ID:", user["user_id"])
        print("Email:", user["email"])
        print("=================================")

        return jsonify({
            "success": True,
            "message": "Password reset successfully"
        }), 200

    except Exception as e:

        print(
            "PASSWORD RESET ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "message": "Failed to reset password",
            "error": str(e)
        }), 500


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    try:

        data = request.get_json() or {}

        email = data.get("email")
        password = data.get("password")

        if (
            not email
            or not password
        ):

            return jsonify({
                "message":
                    "Email and password are required"
            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                password,
                role
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
                "message":
                    "Invalid email or password"
            }), 401

        if not check_password_hash(
            user["password"],
            password
        ):

            return jsonify({
                "message":
                    "Invalid email or password"
            }), 401

        return jsonify({

            "message":
                "Login successful",

            "user": {

                "user_id":
                    user["user_id"],

                "name":
                    user["name"],

                "email":
                    user["email"],

                "role":
                    user["role"]

            }

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Login failed",

            "error":
                str(e)

        }), 500


# =========================================================
# GET ALL USERS
# =========================================================

@app.route(
    "/users",
    methods=["GET"]
)
def get_users():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                family_owner_id
            FROM users
            ORDER BY user_id
            """
        )

        users = cursor.fetchall()

        # A user is shown as a registered face only when
        # their SQL account exists AND their actual face
        # directory contains at least one image.
        for user in users:

            user_face_directory = os.path.join(
                FACES_DIR,
                f"user_{user['user_id']}"
            )

            user["face_registered"] = False

            if os.path.isdir(user_face_directory):

                try:

                    image_files = [
                        filename
                        for filename in os.listdir(
                            user_face_directory
                        )
                        if filename.lower().endswith(
                            (".jpg", ".jpeg", ".png")
                        )
                    ]

                    user["face_registered"] = (
                        len(image_files) > 0
                    )

                except Exception as face_check_error:

                    print(
                        "FACE STATUS CHECK ERROR:",
                        face_check_error
                    )

        return jsonify({
            "users": users
        }), 200

    except Exception as e:

        print(
            "USERS ERROR:",
            e
        )

        return jsonify({
            "users": [],
            "message": "Could not load users."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


@app.route(
    "/face-verification",
    methods=["GET"]
)
def get_face_verification():

    return jsonify({

        "enabled":
            face_verification_enabled

    }), 200


# =========================================================
# FACE VERIFICATION ON / OFF
# =========================================================

@app.route(
    "/face-verification",
    methods=["POST"]
)
def set_face_verification():

    global face_verification_enabled

    try:

        data = request.get_json() or {}

        enabled = data.get(
            "enabled"
        )

        if not isinstance(
            enabled,
            bool
        ):

            return jsonify({

                "message":
                    "enabled must be true or false"

            }), 400

        face_verification_enabled = enabled

        print(
            "FACE VERIFICATION:",
            "ON" if enabled else "OFF"
        )

        return jsonify({

            "message":
                "Face verification status updated",

            "enabled":
                face_verification_enabled

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Failed to update face verification",

            "error":
                str(e)

        }), 500


# =========================================================
# DELETE FACE VERIFICATION
# =========================================================

@app.route(
    "/verify-face-for-delete",
    methods=["POST"]
)
def verify_face_for_delete():

    try:

        data = request.get_json() or {}

        user_id = data.get(
            "user_id"
        )

        if user_id is None:

            return jsonify({

                "verified":
                    False,

                "message":
                    "User ID is required"

            }), 400

        try:

            user_id = int(
                user_id
            )

        except (ValueError, TypeError):

            return jsonify({

                "verified":
                    False,

                "message":
                    "Invalid User ID"

            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                name
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if not user:

            return jsonify({

                "verified":
                    False,

                "message":
                    "User not found"

            }), 404

        return jsonify({

            "verified":
                False,

            "message":
                "Ready for webcam verification",

            "user_id":
                user["user_id"],

            "name":
                user["name"]

        }), 200

    except Exception as e:

        print(
            "DELETE FACE VERIFICATION ERROR:",
            e
        )

        return jsonify({

            "verified":
                False,

            "message":
                "Face verification failed",

            "error":
                str(e)

        }), 500


# =========================================================
# REAL FACE IMAGE VERIFICATION
# =========================================================

@app.route(
    "/verify-face-image",
    methods=["POST"]
)
def verify_face_image():

    try:

        user_id = request.form.get(
            "user_id"
        )

        if user_id is None:

            return jsonify({

                "verified":
                    False,

                "message":
                    "User ID is required"

            }), 400

        try:

            user_id = int(
                user_id
            )

        except (ValueError, TypeError):

            return jsonify({

                "verified":
                    False,

                "message":
                    "Invalid User ID"

            }), 400

        image_file = request.files.get(
            "image"
        )

        if image_file is None:

            return jsonify({

                "verified":
                    False,

                "message":
                    "Face image is required"

            }), 400

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                name
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if not user:

            return jsonify({

                "verified":
                    False,

                "message":
                    "User not found"

            }), 404

        if not os.path.exists(
            TRAINER_PATH
        ):

            return jsonify({

                "verified":
                    False,

                "message":
                    "Face trainer file not found"

            }), 500

        if not os.path.exists(
            CASCADE_PATH
        ):

            return jsonify({

                "verified":
                    False,

                "message":
                    "Haar cascade file not found"

            }), 500

        image_bytes = image_file.read()

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        frame = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if frame is None:

            return jsonify({

                "verified":
                    False,

                "message":
                    "Invalid webcam image"

            }), 400

        if not hasattr(
            cv2,
            "face"
        ):

            return jsonify({

                "verified":
                    False,

                "message":
                    "OpenCV face recognition module is not available"

            }), 500

        recognizer = (
            cv2.face.LBPHFaceRecognizer_create()
        )

        recognizer.read(
            TRAINER_PATH
        )

        face_cascade = (
            cv2.CascadeClassifier(
                CASCADE_PATH
            )
        )

        if face_cascade.empty():

            return jsonify({

                "verified":
                    False,

                "message":
                    "Haar cascade could not be loaded"

            }), 500

        gray = cv2.cvtColor(
            frame,
            cv2.COLOR_BGR2GRAY
        )

        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.3,
            minNeighbors=5
        )

        if len(faces) == 0:

            return jsonify({

                "verified":
                    False,

                "message":
                    "No face detected"

            }), 200

        best_user_id = None
        best_confidence = None

        for (
            x,
            y,
            w,
            h
        ) in faces:

            face = gray[
                y:y + h,
                x:x + w
            ]

            predicted_id, confidence = (
                recognizer.predict(face)
            )

            if (
                best_confidence is None
                or confidence < best_confidence
            ):

                best_user_id = predicted_id
                best_confidence = confidence

        print(
            "================================="
        )

        print(
            "DELETE FACE VERIFICATION"
        )

        print(
            "Selected User ID:",
            user_id
        )

        print(
            "Predicted User ID:",
            best_user_id
        )

        print(
            "Confidence:",
            best_confidence
        )

        print(
            "================================="
        )

        if (
            best_user_id == user_id
            and best_confidence < 60
        ):

            return jsonify({

                "verified":
                    True,

                "message":
                    "Face verified successfully",

                "user_id":
                    user["user_id"],

                "name":
                    user["name"],

                "confidence":
                    round(
                        float(best_confidence),
                        2
                    )

            }), 200

        return jsonify({

            "verified":
                False,

            "message":
                "Face does not match selected user",

            "user_id":
                user["user_id"],

            "name":
                user["name"],

            "confidence":
                round(
                    float(best_confidence),
                    2
                )

        }), 200

    except Exception as e:

        print(
            "REAL FACE VERIFICATION ERROR:",
            e
        )

        return jsonify({

            "verified":
                False,

            "message":
                "Face verification failed",

            "error":
                str(e)

        }), 500


# =========================================================
# ACTUAL DELETE FACE
# =========================================================

@app.route(
    "/delete-face",
    methods=["POST"]
)
def delete_face():

    try:

        # -------------------------------------------------
        # GET USER ID
        # -------------------------------------------------

        user_id = request.form.get(
            "user_id"
        )

        if user_id is None:

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "User ID is required"

            }), 400

        try:

            user_id = int(
                user_id
            )

        except (ValueError, TypeError):

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Invalid User ID"

            }), 400

        # -------------------------------------------------
        # GET IMAGE
        # -------------------------------------------------

        image_file = request.files.get(
            "image"
        )

        if image_file is None:

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Face image is required"

            }), 400

        # -------------------------------------------------
        # CHECK USER
        # -------------------------------------------------

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                name
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if not user:

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "User not found"

            }), 404

        # -------------------------------------------------
        # CHECK TRAINER
        # -------------------------------------------------

        if not os.path.exists(
            TRAINER_PATH
        ):

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Face trainer file not found"

            }), 500

        if not os.path.exists(
            CASCADE_PATH
        ):

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Haar cascade file not found"

            }), 500

        # -------------------------------------------------
        # CHECK OPENCV FACE MODULE
        # -------------------------------------------------

        if not hasattr(
            cv2,
            "face"
        ):

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "OpenCV face recognition module is not available"

            }), 500

        # -------------------------------------------------
        # READ WEBCAM IMAGE
        # -------------------------------------------------

        image_bytes = image_file.read()

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        frame = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if frame is None:

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Invalid webcam image"

            }), 400

        # -------------------------------------------------
        # LOAD MODEL
        # -------------------------------------------------

        recognizer = (
            cv2.face.LBPHFaceRecognizer_create()
        )

        recognizer.read(
            TRAINER_PATH
        )

        face_cascade = (
            cv2.CascadeClassifier(
                CASCADE_PATH
            )
        )

        if face_cascade.empty():

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Haar cascade could not be loaded"

            }), 500

        # -------------------------------------------------
        # DETECT FACE
        # -------------------------------------------------

        gray = cv2.cvtColor(
            frame,
            cv2.COLOR_BGR2GRAY
        )

        detected_faces = (
            face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.3,
                minNeighbors=5
            )
        )

        if len(detected_faces) == 0:

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "No face detected"

            }), 200

        # -------------------------------------------------
        # RECOGNIZE FACE
        # -------------------------------------------------

        best_user_id = None
        best_confidence = None

        for (
            x,
            y,
            w,
            h
        ) in detected_faces:

            face = gray[
                y:y + h,
                x:x + w
            ]

            predicted_id, confidence = (
                recognizer.predict(face)
            )

            if (
                best_confidence is None
                or confidence < best_confidence
            ):

                best_user_id = predicted_id
                best_confidence = confidence

        print(
            "================================="
        )

        print(
            "SECURE FACE DELETE REQUEST"
        )

        print(
            "Selected User ID:",
            user_id
        )

        print(
            "Predicted User ID:",
            best_user_id
        )

        print(
            "Confidence:",
            best_confidence
        )

        print(
            "================================="
        )

        # -------------------------------------------------
        # SECURITY CHECK
        # -------------------------------------------------

        if (
            best_user_id != user_id
            or best_confidence >= 60
        ):

            return jsonify({

                "deleted":
                    False,

                "verified":
                    False,

                "message":
                    "Face verification failed. Nothing was deleted.",

                "confidence":
                    round(
                        float(best_confidence),
                        2
                    )

            }), 200

        # -------------------------------------------------
        # FACE VERIFIED
        # -------------------------------------------------

        print(
            "FACE VERIFIED."
        )

        print(
            "Proceeding with face deletion."
        )

        # -------------------------------------------------
        # FACE DIRECTORY
        # -------------------------------------------------

        user_face_directory = os.path.join(
            FACES_DIR,
            f"user_{user_id}"
        )

        if not os.path.exists(
            user_face_directory
        ):

            return jsonify({

                "deleted":
                    False,

                "verified":
                    True,

                "message":
                    "Face verified, but no registered face directory was found."

            }), 404

        # -------------------------------------------------
        # DELETE FACE DIRECTORY
        # -------------------------------------------------

        shutil.rmtree(
            user_face_directory
        )

        print(
            "FACE DIRECTORY DELETED:"
        )

        print(
            user_face_directory
        )

        # -------------------------------------------------
        # RETRAIN MODEL
        # -------------------------------------------------

        retrain_success = (
            retrain_face_model()
        )

        if not retrain_success:

            return jsonify({

                "deleted":
                    True,

                "verified":
                    True,

                "message":
                    (
                        "Face images were deleted, "
                        "but the face model could not be retrained."
                    ),

                "warning":
                    True

            }), 200

        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        print(
            "================================="
        )

        print(
            "FACE DELETED SUCCESSFULLY"
        )

        print(
            "User ID:",
            user_id
        )

        print(
            "User:",
            user["name"]
        )

        print(
            "================================="
        )

        return jsonify({

            "deleted":
                True,

            "verified":
                True,

            "message":
                (
                    "Face deleted successfully. "
                    "User account was kept."
                ),

            "user_id":
                user["user_id"],

            "name":
                user["name"],

            "confidence":
                round(
                    float(best_confidence),
                    2
                )

        }), 200

    except Exception as e:

        print(
            "DELETE FACE ERROR:",
            e
        )

        return jsonify({

            "deleted":
                False,

            "verified":
                False,

            "message":
                "Face deletion failed",

            "error":
                str(e)

        }), 500


# =========================================================
# ESP32 STATUS
# =========================================================

@app.route(
    "/esp32-status",
    methods=["GET"]
)
def esp32_status():

    try:

        status = get_cached_esp32_status()

        gas_value = status.get("gas")
        gas_status = process_gas_status(
            gas_value
        )

        if not status.get("online"):
            return jsonify({

                "esp32":
                    "OFFLINE",

                "lock_status":
                    status.get(
                        "lock_status",
                        "UNKNOWN"
                    ),

                "door_status":
                    status.get(
                        "door_status",
                        "UNKNOWN"
                    ),

                "temperature":
                    status.get(
                        "temperature"
                    ),

                "humidity":
                    status.get(
                        "humidity"
                    ),

                "gas":
                    gas_value,

                "gas_status":
                    gas_status,

                "motion":
                    status.get(
                        "motion",
                        "UNKNOWN"
                    ),

                "updated_at":
                    status.get(
                        "updated_at"
                    )

            }), 503

        return jsonify({

            "esp32":
                "ONLINE",

            "lock_status":
                status.get(
                    "lock_status",
                    "UNKNOWN"
                ),

            "door_status":
                status.get(
                    "door_status",
                    "UNKNOWN"
                ),

            "temperature":
                status.get(
                    "temperature"
                ),

            "humidity":
                status.get(
                    "humidity"
                ),

            "gas":
                gas_value,

            "gas_status":
                gas_status,

            "motion":
                status.get(
                    "motion",
                    "UNKNOWN"
                ),

            "updated_at":
                status.get(
                    "updated_at"
                )

        }), 200

    except Exception as e:

        print(
            "ESP32 STATUS ERROR:",
            e
        )

        return jsonify({

            "esp32":
                "OFFLINE",

            "lock_status":
                "UNKNOWN",

            "door_status":
                "UNKNOWN",

            "temperature":
                None,

            "humidity":
                None,

            "gas":
                None,

            "gas_status":
                "UNKNOWN",

            "motion":
                "UNKNOWN",

            "error":
                str(e)

        }), 503


# =========================================================
# DOOR STATUS
# =========================================================

@app.route(
    "/door-status",
    methods=["GET"]
)
def door_status():

    try:

        status = get_cached_esp32_status()

        gas_value = status.get("gas")
        gas_status = process_gas_status(
            gas_value
        )

        if not status.get("online"):

            return jsonify({

                "esp32":
                    "OFFLINE",

                "event_type":
                    "DOOR_STATUS",

                "lock_status":
                    status.get(
                        "lock_status",
                        "UNKNOWN"
                    ),

                "door_status":
                    status.get(
                        "door_status",
                        "UNKNOWN"
                    ),

                "temperature":
                    status.get(
                        "temperature"
                    ),

                "humidity":
                    status.get(
                        "humidity"
                    ),

                "gas":
                    gas_value,

                "gas_status":
                    gas_status,

                "motion":
                    status.get(
                        "motion",
                        "UNKNOWN"
                    ),

                "updated_at":
                    status.get(
                        "updated_at"
                    )

            }), 503

        return jsonify({

            "esp32":
                "CONNECTED",

            "event_type":
                "DOOR_STATUS",

            "lock_status":
                status.get(
                    "lock_status",
                    "UNKNOWN"
                ),

            "door_status":
                status.get(
                    "door_status",
                    "UNKNOWN"
                ),

            "temperature":
                status.get(
                    "temperature"
                ),

            "humidity":
                status.get(
                    "humidity"
                ),

            "gas":
                gas_value,

            "gas_status":
                gas_status,

            "motion":
                status.get(
                    "motion",
                    "UNKNOWN"
                ),

            "updated_at":
                status.get(
                    "updated_at"
                )

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Failed to get door status",

            "error":
                str(e)

        }), 500


# =========================================================
# DOOR PIN STATUS
# =========================================================

@app.route(
    "/door-pin/status",
    methods=["GET"]
)
def door_pin_status():

    try:
        user_id = request.args.get("user_id")

        if user_id is None:
            return jsonify({
                "success": False,
                "message": "User ID is required"
            }), 400

        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({
                "success": False,
                "message": "Invalid user ID"
            }), 400

        pin_hash = get_door_pin_hash(user_id)

        return jsonify({
            "success": True,
            "configured": pin_hash is not None
        }), 200

    except Exception as e:
        print("DOOR PIN STATUS ERROR:", e)
        return jsonify({
            "success": False,
            "message": "Failed to get PIN status",
            "error": str(e)
        }), 500


# =========================================================
# SET / CHANGE DOOR PIN
# =========================================================

@app.route(
    "/door-pin/set",
    methods=["POST"]
)
def set_door_pin():

    try:
        data = request.get_json() or {}
        user_id = data.get("user_id")
        current_pin = data.get("current_pin")
        new_pin = data.get("new_pin")

        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({
                "success": False,
                "message": "Invalid user ID"
            }), 400

        if not valid_pin(new_pin):
            return jsonify({
                "success": False,
                "message": "PIN must be exactly 6 digits"
            }), 400

        existing_hash = get_door_pin_hash(user_id)

        # First-time setup: no current PIN exists yet.
        if existing_hash is None:
            if current_pin not in (None, ""):
                return jsonify({
                    "success": False,
                    "message": "No existing PIN is configured"
                }), 400
        else:
            # Changing an existing PIN requires the current PIN.
            if not valid_pin(current_pin):
                return jsonify({
                    "success": False,
                    "message": "Current PIN is required"
                }), 401

            if not check_password_hash(existing_hash, current_pin):
                return jsonify({
                    "success": False,
                    "message": "Current PIN is incorrect"
                }), 401

        if existing_hash is not None and current_pin == new_pin:
            return jsonify({
                "success": False,
                "message": "New PIN must be different from the current PIN"
            }), 400

        new_hash = generate_password_hash(new_pin)

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO door_pins (user_id, pin_hash)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE
                pin_hash = VALUES(pin_hash),
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, new_hash)
        )

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({
            "success": True,
            "message": "PIN set successfully" if existing_hash is None else "PIN changed successfully",
            "configured": True
        }), 200

    except Exception as e:
        print("SET/CHANGE DOOR PIN ERROR:", e)
        return jsonify({
            "success": False,
            "message": "Failed to save PIN",
            "error": str(e)
        }), 500


# =========================================================
# RESET DOOR PIN - ACCOUNT PASSWORD REQUIRED
# =========================================================

@app.route(
    "/door-pin/reset",
    methods=["POST"]
)
def reset_door_pin():

    try:
        data = request.get_json() or {}
        user_id = data.get("user_id")
        account_password = data.get("account_password")
        new_pin = data.get("new_pin")

        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({
                "success": False,
                "message": "Invalid user ID"
            }), 400

        if not account_password:
            return jsonify({
                "success": False,
                "message": "Account password is required for PIN reset"
            }), 401

        if not valid_pin(new_pin):
            return jsonify({
                "success": False,
                "message": "PIN must be exactly 6 digits"
            }), 400

        password_hash = get_user_password_hash(user_id)

        if not password_hash:
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404

        if not check_password_hash(password_hash, account_password):
            return jsonify({
                "success": False,
                "message": "Account password is incorrect"
            }), 401

        new_hash = generate_password_hash(new_pin)

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO door_pins (user_id, pin_hash)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE
                pin_hash = VALUES(pin_hash),
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, new_hash)
        )

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({
            "success": True,
            "message": "PIN reset successfully",
            "configured": True
        }), 200

    except Exception as e:
        print("RESET DOOR PIN ERROR:", e)
        return jsonify({
            "success": False,
            "message": "Failed to reset PIN",
            "error": str(e)
        }), 500


# =========================================================
# DOOR CONTROL
# =========================================================

@app.route(
    "/door-control",
    methods=["POST"]
)
def door_control():

    try:

        data = request.get_json() or {}
        action = data.get("action")
        user_id = data.get("user_id")
        pin = data.get("pin")

        if user_id is not None:
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                return jsonify({
                    "message": "Invalid user ID"
                }), 400

        if action not in ["LOCK", "UNLOCK"]:
            return jsonify({
                "message": "Invalid action"
            }), 400

        # LOCK does not require a PIN.
        if action == "UNLOCK":

            if user_id is None:
                return jsonify({
                    "message": (
                        "User ID is required to unlock the door"
                    )
                }), 400

            if not valid_pin(pin):
                return jsonify({
                    "message": (
                        "A valid 6-digit PIN is required "
                        "to unlock the door"
                    )
                }), 401

            # -------------------------------------------------
            # FAMILY PIN LOGIC
            #
            # A family member uses the family owner's door PIN.
            # The access log still stores the actual recognized
            # user's ID.
            # -------------------------------------------------

            connection = get_db_connection()
            cursor = connection.cursor(
                dictionary=True
            )

            cursor.execute(
                """
                SELECT
                    user_id,
                    name,
                    family_owner_id
                FROM users
                WHERE user_id = %s
                """,
                (user_id,)
            )

            recognized_user = cursor.fetchone()

            cursor.close()
            connection.close()

            if not recognized_user:
                return jsonify({
                    "message":
                        "User account not found"
                }), 404

            pin_owner_id = (
                recognized_user.get(
                    "family_owner_id"
                )
            )

            if pin_owner_id is None:
                pin_owner_id = user_id

            stored_pin_hash = get_door_pin_hash(
                pin_owner_id
            )

            if stored_pin_hash is None:
                return jsonify({
                    "message":
                        "No family owner's door PIN is configured"
                }), 403

            if not check_password_hash(
                stored_pin_hash,
                pin
            ):
                return jsonify({
                    "message":
                        "Incorrect family door PIN"
                }), 401

            print(
                "DOOR PIN AUTHORIZATION"
            )

            print(
                "Recognized User ID:",
                user_id
            )

            print(
                "Recognized User:",
                recognized_user.get(
                    "name"
                )
            )

            print(
                "PIN Owner User ID:",
                pin_owner_id
            )

        # -------------------------------------------------
        # SEND COMMAND THROUGH CLOUD QUEUE
        # -------------------------------------------------

        if action == "LOCK":
            esp32_response = send_esp32_command(
                "/lock"
            )
        else:
            esp32_response = send_esp32_command(
                "/unlock"
            )

        if esp32_response is None:
            return jsonify({
                "message": (
                    "ESP32 is offline or did not "
                    "execute the command in time"
                ),
                "lock_status": "UNKNOWN",
                "door_status": "UNKNOWN"
            }), 503

        expected_response = (
            "LOCKED"
            if action == "LOCK"
            else "UNLOCKED"
        )

        if expected_response not in esp32_response:
            return jsonify({
                "message":
                    "ESP32 returned unexpected response",
                "esp32_response":
                    esp32_response
            }), 500

        lock_status = expected_response

        # -------------------------------------------------
        # SAVE ACCESS LOG
        # -------------------------------------------------

        try:

            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO door_events
                (
                    event_type,
                    status,
                    user_id
                )
                VALUES
                (%s, %s, %s)
                """,
                (
                    "DOOR_CONTROL",
                    lock_status,
                    user_id
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            print(
                "ACCESS LOG SAVED"
            )

            print(
                "Event Type:",
                "DOOR_CONTROL"
            )

            print(
                "Status:",
                lock_status
            )

            print(
                "User ID:",
                user_id
            )

        except Exception as db_error:

            print(
                "DATABASE LOG ERROR:",
                db_error
            )

        # Read the latest cached status.
        status_response = send_esp32_command(
            "/status"
        )

        door_status_value = "UNKNOWN"

        if status_response:

            try:

                status_data = json.loads(
                    status_response
                )

                door_status_value = (
                    status_data.get(
                        "door_status",
                        "UNKNOWN"
                    )
                )

                gas_value = (
                    status_data.get(
                        "gas"
                    )
                )

                process_gas_status(
                    gas_value
                )

            except Exception:
                pass

        return jsonify({

            "message":
                "Door " + lock_status.lower(),

            "lock_status":
                lock_status,

            "door_status":
                door_status_value,

            "esp32":
                "CONNECTED",

            "user_id":
                user_id

        }), 200

    except Exception as e:

        print(
            "DOOR CONTROL ERROR:",
            e
        )

        return jsonify({

            "message":
                "Door control failed",

            "error":
                str(e)

        }), 500


# =========================================================
# CREATE ALERT
# =========================================================

@app.route(
    "/create-alert",
    methods=["POST"]
)
def create_alert():

    try:

        data = request.get_json() or {}

        alert_type = data.get(
            "alert_type"
        )

        severity = data.get(
            "severity"
        )

        message = data.get(
            "message"
        )

        user_id = data.get(
            "user_id",
            2
        )

        if (
            not alert_type
            or not severity
            or not message
        ):

            return jsonify({

                "message":
                    "Alert details are required"

            }), 400

        connection = (
            get_db_connection()
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO alerts
            (
                alert_type,
                severity,
                message,
                status,
                user_id
            )
            VALUES
            (
                %s,
                %s,
                %s,
                'ACTIVE',
                %s
            )
            """,
            (
                alert_type,
                severity,
                message,
                user_id
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({

            "message":
                "Alert created successfully"

        }), 201

    except Exception as e:

        return jsonify({

            "message":
                "Failed to create alert",

            "error":
                str(e)

        }), 500


# =========================================================
# GET ACTIVE ALERTS
# =========================================================

@app.route(
    "/alerts",
    methods=["GET"]
)
def get_alerts():

    try:

        connection = (
            get_db_connection()
        )

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                alert_id,
                alert_type,
                severity,
                message,
                status,
                user_id,
                timestamp
            FROM alerts
            WHERE status = 'ACTIVE'
            ORDER BY timestamp DESC
            """
        )

        alerts = cursor.fetchall()

        cursor.close()
        connection.close()

        for alert in alerts:

            if alert["timestamp"]:

                alert["timestamp"] = (
                    alert["timestamp"]
                    .isoformat()
                )

        return jsonify({

            "alerts":
                alerts

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Failed to get alerts",

            "error":
                str(e)

        }), 500


# =========================================================
# ACCESS LOGS
# =========================================================

@app.route(
    "/access-logs",
    methods=["GET"]
)
def access_logs():

    try:

        connection = (
            get_db_connection()
        )

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                event_id,
                event_type,
                status,
                user_id,
                timestamp
            FROM door_events
            ORDER BY timestamp DESC
            """
        )

        logs = cursor.fetchall()

        cursor.close()
        connection.close()

        for log in logs:

            if log["timestamp"]:

                log["timestamp"] = (
                    log["timestamp"]
                    .isoformat()
                )

        return jsonify({

            "logs":
                logs

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Failed to get access logs",

            "error":
                str(e)

        }), 500


# =========================================================
# REED SWITCH SENSOR
# =========================================================

@app.route(
    "/sensor/door",
    methods=["POST"]
)
def sensor_door():

    try:

        data = request.get_json() or {}

        door_status = data.get(
            "door_status"
        )

        if door_status not in [
            "OPEN",
            "CLOSED"
        ]:

            return jsonify({

                "message":
                    "Invalid door status"

            }), 400

        connection = (
            get_db_connection()
        )

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT status
            FROM door_events
            WHERE event_type =
                  'DOOR_SENSOR'
            ORDER BY timestamp DESC
            LIMIT 1
            """
        )

        last_event = cursor.fetchone()

        if (
            last_event
            and last_event["status"]
            == door_status
        ):

            cursor.close()
            connection.close()

            return jsonify({

                "message":
                    "Door status unchanged",

                "door_status":
                    door_status,

                "logged":
                    False

            }), 200

        cursor.execute(
            """
            INSERT INTO door_events
            (
                event_type,
                status,
                user_id
            )
            VALUES
            (%s, %s, %s)
            """,
            (
                "DOOR_SENSOR",
                door_status,
                2
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return jsonify({

            "message":
                "Door sensor event saved",

            "door_status":
                door_status,

            "logged":
                True

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Failed to save door sensor event",

            "error":
                str(e)

        }), 500


# =========================================================
# SENSOR DATA
# =========================================================

@app.route(
    "/sensor/data",
    methods=["POST"]
)
def sensor_data():

    try:

        data = request.get_json() or {}

        temperature = data.get(
            "temperature"
        )

        humidity = data.get(
            "humidity"
        )

        gas = data.get(
            "gas"
        )

        motion = data.get(
            "motion"
        )

        door_status = data.get(
            "door_status"
        )
        if gas is not None:

            gas = float(
                gas
            )

            gas_status = process_gas_status(
                gas
            )

        else:

            gas_status = "UNKNOWN"
        try:

            connection = (
                get_db_connection()
            )

            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO sensor_data
                (
                    temperature,
                    humidity,
                    gas,
                    motion,
                    door_status
                )
                VALUES
                (%s, %s, %s, %s, %s)
                """,
                (
                    temperature,
                    humidity,
                    gas,
                    motion,
                    door_status
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

        except Exception as db_error:

            print(
                "SENSOR DATA DB ERROR:",
                db_error
            )

        return jsonify({

            "message":
                "Sensor data received",

            "temperature":
                temperature,

            "humidity":
                humidity,

            "gas":
                gas,

            "gas_status":
                gas_status,

            "motion":
                motion,

            "door_status":
                door_status

        }), 200

    except Exception as e:

        return jsonify({

            "message":
                "Failed to process sensor data",

            "error":
                str(e)

        }), 500


# =========================================================
# AI HOME ASSISTANT - NOVA LOCAL OLLAMA BACKEND
# =========================================================

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OLLAMA_MODEL = "llama3.2:3b"


def get_home_ai_context():
    """Collect live ESP32 data and recent MySQL records for NOVA."""
    context = {
        "esp32": {},
        "active_alerts": [],
        "recent_access_logs": [],
        "recent_sensor_data": []
    }

    # ---------------------------------------------------------
    # Live ESP32 status
    # ---------------------------------------------------------
    try:
        status = get_cached_esp32_status()

        if status.get("updated_at"):
            gas_value = status.get("gas")

            context["esp32"] = {
                "online": bool(status.get("online")),
                "lock_status": status.get(
                    "lock_status",
                    "UNKNOWN"
                ),
                "door_status": status.get(
                    "door_status",
                    "UNKNOWN"
                ),
                "temperature": status.get(
                    "temperature"
                ),
                "humidity": status.get(
                    "humidity"
                ),
                "gas": gas_value,
                "gas_status": process_gas_status(
                    gas_value
                ),
                "motion": status.get(
                    "motion",
                    "UNKNOWN"
                )
            }

        else:
            context["esp32"] = {
                "online": False
            }

    except Exception as e:
        context["esp32"] = {
            "online": False,
            "error": str(e)
        }

    # ---------------------------------------------------------
    # Recent database information
    # ---------------------------------------------------------
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                alert_id,
                alert_type,
                severity,
                message,
                status,
                user_id,
                timestamp
            FROM alerts
            WHERE status = 'ACTIVE'
            ORDER BY timestamp DESC
            LIMIT 10
        """)

        context["active_alerts"] = cursor.fetchall()

        cursor.execute("""
            SELECT
                event_id,
                event_type,
                status,
                user_id,
                timestamp
            FROM door_events
            ORDER BY timestamp DESC
            LIMIT 10
        """)

        context["recent_access_logs"] = cursor.fetchall()

        cursor.execute("""
            SELECT
                temperature,
                humidity,
                gas,
                motion,
                door_status,
                timestamp
            FROM sensor_data
            ORDER BY timestamp DESC
            LIMIT 10
        """)

        context["recent_sensor_data"] = cursor.fetchall()

        cursor.close()
        connection.close()

    except Exception as e:
        context["database_error"] = str(e)

    for group in [
        "active_alerts",
        "recent_access_logs",
        "recent_sensor_data"
    ]:
        for item in context[group]:
            if item.get("timestamp"):
                item["timestamp"] = item["timestamp"].isoformat()

    return context


def answer_home_question(message, context):
    """
    Send the user's message and the current home-safety context
    to the local Ollama model so NOVA can respond naturally.
    """

    raw_message = (message or "").strip()

    if not raw_message:
        return (
            "Hey Arun! I'm NOVA. "
            "I'm ready to talk with you about your home."
        )

    # Handle short conversational messages locally so Ollama does not
    # generate long or unrelated replies for simple greetings.
    normalized_message = " ".join(raw_message.lower().split())

    greeting_messages = {
        "hi",
        "hello",
        "hey",
        "hai",
        "hii",
        "hi nova",
        "hello nova",
        "hey nova",
        "hai nova",
        "hii nova",
        "hey nova!",
        "hi nova!",
        "hello nova!",
        "hai nova!",
        "hii nova!",
    }

    simple_replies = {
        "thanks": "You're welcome, Arun! ",
        "thank you": "You're welcome, Arun! ",
        "ok": "Okay, Arun. ",
        "okay": "Okay, Arun. ",
        "no": "Alright, Arun. ",
        "yes": "Got it, Arun. ",
    }

    if normalized_message in greeting_messages:
        return "Hey Arun! "

    if normalized_message in simple_replies:
        return simple_replies[normalized_message]

    # ---------------------------------------------------------
    # DETERMINISTIC SAFETY ANSWERS
    # Use live ESP32 values directly for critical status questions.
    # Do not let the language model guess door/lock state.
    # ---------------------------------------------------------
    live_esp32 = context.get("esp32", {}) or {}
    live_lock_status = str(live_esp32.get("lock_status", "UNKNOWN")).upper()
    live_door_status = str(live_esp32.get("door_status", "UNKNOWN")).upper()
    live_online = bool(live_esp32.get("online", False))
    live_alerts = context.get("active_alerts", []) or []
    live_gas_status = str(live_esp32.get("gas_status", "UNKNOWN")).upper()
    live_motion = str(live_esp32.get("motion", "UNKNOWN")).upper()

    door_question_phrases = {
        "is the door locked",
        "is my door locked",
        "door locked",
        "is the lock locked",
        "is my lock locked",
        "what is the door lock status",
        "what's the door lock status",
        "what is my door lock status",
        "what's my door lock status",
    }

    if normalized_message.rstrip("?!.") in door_question_phrases:
        if not live_online:
            return "I can't confirm the door lock status because the ESP32 is offline."
        if live_lock_status == "LOCKED":
            return "The door is currently locked."
        if live_lock_status == "UNLOCKED":
            return "The door is currently unlocked."
        return "I can't confirm the door lock status right now."

    safe_question_phrases = {
        "is my home safe",
        "is the home safe",
        "is my house safe",
        "is the house safe",
        "is everything safe",
        "is everything okay",
        "is everything ok",
        "is my home okay",
        "is my home ok",
    }

    if normalized_message.rstrip("?!.") in safe_question_phrases:
        if not live_online:
            return "I can't confirm home safety because the ESP32 is offline."

        safety_issues = []

        if live_lock_status == "UNLOCKED":
            safety_issues.append("the door is unlocked")
        elif live_lock_status == "UNKNOWN":
            safety_issues.append("the door lock status is unknown")

        if live_gas_status == "DANGER":
            safety_issues.append("a gas or smoke danger is detected")

        if live_alerts:
            safety_issues.append(f"{len(live_alerts)} active safety alert{'s' if len(live_alerts) != 1 else ''}")

        if safety_issues:
            if len(safety_issues) == 1:
                return "Your home has a safety issue right now: " + safety_issues[0] + "."
            return "Your home has some safety issues right now: " + "; ".join(safety_issues) + "."

        if live_door_status == "OPEN":
            return "Your home has no active safety alerts, but the door is currently open."

        return "Your home currently has no active safety alerts and the door is locked."

    system_prompt = """
You are NOVA, a friendly AI buddy built into Arun's Smart Home Safety System.

Your job is to talk naturally like a helpful home-safety companion, NOT like
a database or sensor dashboard.

IMPORTANT RULES:
1. Use the live home data supplied in the HOME CONTEXT.
2. Answer the user's actual question first.
3. Do not simply repeat every sensor value when the user asks a simple question.
4. Explain what the data means in natural language.
5. Be warm, concise, and conversational.
6. You may use a small number of emojis when they genuinely help, but do not
   fill the response with emojis.
7. Never claim that you performed an action unless the backend actually did it.
8. You cannot physically unlock, lock, delete faces, or control devices through
   this conversation endpoint. If the user asks for an action, clearly explain
   that the current NOVA chat can report the status but cannot perform that
   action unless a dedicated control endpoint is used.
9. If the ESP32 is offline, clearly say that live safety information cannot be
   confirmed.
10. For gas/smoke danger, be clear and safety-focused. Do not minimize a
    dangerous reading.
11. If motion is detected, do not automatically call it an intrusion. Explain
    that motion is detected and that the user should check the context.
12. Never invent sensor readings, users, alerts, timestamps, or events.
13. If the user asks something unrelated to the smart home, answer normally
    when possible, while keeping the NOVA personality.
14. Do not mention "HOME CONTEXT", JSON, prompts, APIs, Ollama, models, or
    backend implementation details to the user.
15. Your normal reply MUST be 1 or 2 short sentences.
16. For simple factual questions, use exactly ONE short sentence.
17. Do not ask a follow-up question.
18. Do not speculate about what a person did, why they acted, or who may be using the home.
19. Do not mention recent history unless the user asks about recent activity.
20. Do not give lists or paragraphs unless the user explicitly asks for details.
21. Do not repeat the user's question.

You are a conversational buddy. For example:
User: "Is my home safe?"
Good style: " Your home looks safe right now. There are no active safety alerts."

User: "What's the temperature?"
Good style: "🌡️ It's 31.6°C right now."

User: "Is the door locked?"
Good style: "🔒 Yes, the door is currently locked."

User: "I'm worried, what happened?"
Good style: Give only the relevant safety issue in 1-2 short sentences.
"""

    # Convert the current ESP32/MySQL information into a compact,
    # readable representation for the local model.
    try:
        home_context = json.dumps(
            context,
            ensure_ascii=False,
            indent=2,
            default=str
        )
    except Exception:
        home_context = str(context)

    user_prompt = f"""
Here is the current live information from the Smart Home Safety System:

HOME CONTEXT:
{home_context}

USER MESSAGE:
{raw_message}

Respond as NOVA, Arun's friendly smart-home safety buddy.
"""

    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": system_prompt.strip()
            },
            {
                "role": "user",
                "content": user_prompt.strip()
            }
        ],
        "options": {
            "temperature": 0.2,
            "num_predict": 70
        }
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        result = response.json()

        reply = (
            result.get("message", {})
            .get("content", "")
            .strip()
        )

        if reply:
            # Hard safety/UX limit: NOVA should remain a short buddy.
            # Keep at most the first two sentences and remove follow-up questions.
            reply = reply.replace("\n", " ").strip()
            import re
            parts = re.split(r"(?<=[.!?])\s+", reply)
            kept = []
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if part.endswith("?"):
                    continue
                kept.append(part)
                if len(kept) >= 2:
                    break
            compact = " ".join(kept).strip()
            if compact:
                return compact
            return reply[:220].strip()

        print("NOVA ERROR: Ollama returned an empty response.")
        return (
            "I'm here, Arun, but I didn't get a proper response from my "
            "local AI just now. Please try that again."
        )

    except requests.exceptions.ConnectionError:
        print("NOVA ERROR: Ollama is not running.")
        return (
            "I can't reach my local AI engine right now. "
            "Please make sure Ollama is running on your Mac."
        )

    except requests.exceptions.Timeout:
        print("NOVA ERROR: Ollama request timed out.")
        return (
            "I'm taking a little too long to respond right now. "
            "Please try again in a moment."
        )

    except requests.exceptions.RequestException as e:
        print("NOVA OLLAMA REQUEST ERROR:", e)
        return (
            "I couldn't connect to my local AI engine right now. "
            "Please try again in a moment."
        )

    except Exception as e:
        print("NOVA AI ERROR:", e)
        return (
            "Something went wrong while I was thinking. "
            "Please try asking me again."
        )


@app.route("/ai-assistant", methods=["POST"])
def ai_assistant():
    """Answer home-safety questions using NOVA + live ESP32/MySQL data."""

    try:
        data = request.get_json() or {}
        message = data.get("message", "")

        if not isinstance(message, str) or not message.strip():
            return jsonify({
                "success": False,
                "message": "A question or message is required"
            }), 400

        context = get_home_ai_context()
        reply = answer_home_question(message, context)

        return jsonify({
            "success": True,
            "reply": reply,
            "data_source": "ESP32 + MySQL",
            "ai_api_connected": True,
            "ai_engine": "Ollama",
            "ai_model": OLLAMA_MODEL
        }), 200

    except Exception as e:
        print("AI ASSISTANT ERROR:", e)

        return jsonify({
            "success": False,
            "message": "NOVA assistant failed",
            "error": str(e)
        }), 500


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )