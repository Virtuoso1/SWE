import mysql.connector #type: ignore
from mysql.connector import Error #type: ignore
from dotenv import load_dotenv #type: ignore
from pathlib import Path
import os

# Load env
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

def create_database_if_missing(silent = False):
    db_name = os.getenv("DB_NAME")
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD")
        )
        cursor = conn.cursor()
        if not silent:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        if not silent:
            print(f"Database '{db_name}' is ready.")
        cursor.close()
        conn.close()
    except Error as e:
        if not silent:
            print("Error while creating database:", e)

def get_connection(silent = False):
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
        return conn
    except Error as e:
        if not silent:
            print("Database connection error:", e)
        return None

def init_db(silent = False):
    create_database_if_missing(silent)
    conn = get_connection(silent)
    if not conn:
        if not silent:
            print("Could not connect to database.")
        return

    cursor = conn.cursor()
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as schema_file:
        sql_script = schema_file.read()

    for statement in sql_script.split(";"):
        stmt = statement.strip()
        if stmt:
            try:
                cursor.execute(stmt)
            except Error as e:
                if not silent:
                    print("Error executing SQL statement:", e)

    conn.commit()
    cursor.close()
    conn.close()
    if not silent:
        if not silent:
            print("Tables initialized successfully.")