import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

DATABASE = 'datablock.db'

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("Database initialized successfully!")

class User(UserMixin):
    """User model for Flask-Login."""

    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash

    @staticmethod
    def get_by_id(user_id):
        """Get user by ID."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(row['id'], row['username'], row['email'], row['password_hash'])
        return None

    @staticmethod
    def get_by_username(username):
        """Get user by username."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(row['id'], row['username'], row['email'], row['password_hash'])
        return None

    @staticmethod
    def get_by_email(email):
        """Get user by email."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(row['id'], row['username'], row['email'], row['password_hash'])
        return None

    @staticmethod
    def create(username, email, password):
        """Create a new user."""
        conn = get_db()
        cursor = conn.cursor()

        password_hash = generate_password_hash(password)

        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return User.get_by_id(user_id)
        except sqlite3.IntegrityError:
            conn.close()
            return None

    def check_password(self, password):
        """Check if the provided password matches the hash."""
        return check_password_hash(self.password_hash, password)
