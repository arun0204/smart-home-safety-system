import mysql.connector


def get_db_connection():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="smart_home_safety"
    )

    return connection