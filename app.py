import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
load_dotenv()


SECRET_KEY = os.getenv('SECRET_KEY')
DATABASE_URI = os.getenv('DATABASE_URI')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))



app = Flask(__name__)
CORS(app)  # Allow cross-origin requests (important for frontend and backend on different ports)

# Secret key for encoding and decoding JWT tokens
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this in production to something secure

# Create a folder for database if it doesn't exist
if not os.path.exists('data'):
    os.makedirs('data')

# SQLite Database File Location
DB_PATH = os.path.join('data', 'events.db')

# Function to connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Enables column access by name (e.g., user['email'])
    return conn

# Create necessary tables if they do not exist
def create_tables():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        description TEXT NOT NULL,
                        date TEXT NOT NULL)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS rsvps (
                        user_id INTEGER,
                        event_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (event_id) REFERENCES events(id),
                        PRIMARY KEY (user_id, event_id))''')
    conn.commit()
    conn.close()

create_tables()

# Route for user signup (creating a new user)
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()  # Get data from the frontend

        # Ensure necessary fields are provided
        if not data.get('name') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Name, email, and password are required'}), 400

        name = data['name']
        email = data['email']
        password = data['password']

        # Check if the user already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if existing_user:
            return jsonify({'message': 'User already exists'}), 400

        # Hash the password and store the new user in the database
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        conn.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
        conn.commit()
        conn.close()

        return jsonify({'message': 'User created successfully'}), 201

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Route for user login (authenticate user and return a JWT token)
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        # Ensure email and password are provided
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400

        email = data['email']
        password = data['password']

        # Fetch user from the database by email
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        # Verify if the user exists and the password matches
        if user and check_password_hash(user['password'], password):
            # Create JWT token with 1-hour expiration
            token = jwt.encode({
                'sub': user['id'],  # User ID is stored as 'sub' (subject)
                'exp': datetime.utcnow() + timedelta(hours=1)  # Token expiration time
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({'access_token': token})  # Return the token in the response
        else:
            return jsonify({'message': 'Invalid email or password'}), 401

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Route to get all events
@app.route('/api/events', methods=['GET'])
def get_events():
    try:
        conn = get_db_connection()
        events = conn.execute('SELECT * FROM events').fetchall()
        conn.close()

        if events:
            event_list = [{'id': event['id'], 'name': event['name'], 'description': event['description'], 'date': event['date']} for event in events]
            return jsonify({'events': event_list}), 200
        else:
            return jsonify({'message': 'No events found'}), 404

    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Route to RSVP to an event (requires JWT token)
@app.route('/api/events/<int:event_id>/rsvp', methods=['POST'])
def rsvp(event_id):
    try:
        # Get the token from the Authorization header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403

        # Decode the JWT token to get user info
        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded_token['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 403

        # Check if the user has already RSVP'd for this event
        conn = get_db_connection()
        existing_rsvp = conn.execute('SELECT * FROM rsvps WHERE user_id = ? AND event_id = ?', (user_id, event_id)).fetchone()

        if existing_rsvp:
            return jsonify({'message': 'You have already RSVP\'d for this event'}), 400

        # Add the RSVP record to the database
        conn.execute('INSERT INTO rsvps (user_id, event_id) VALUES (?, ?)', (user_id, event_id))
        conn.commit()
        conn.close()

        return jsonify({'message': 'RSVP successful'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)