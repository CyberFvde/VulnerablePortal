from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

# Ensure we have a secret key
if not os.environ.get("SESSION_SECRET"):
    logging.warning("SESSION_SECRET not set! Using a temporary secret key.")
    app.secret_key = os.urandom(24)
else:
    app.secret_key = os.environ.get("SESSION_SECRET")
    logging.info("Session secret key configured successfully")

# Configure session for development
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_SECURE'] = False  # Allow non-HTTPS in development
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configure PostgreSQL database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

db.init_app(app)

# Import models after db initialization
from models import User

# Initialize database
with app.app_context():
    db.create_all()
    logging.info("Database tables created successfully")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('warning.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip()

        # Validate input
        if not username or not password or not email:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))

        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username.lower()).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email.lower()).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        try:
            # Create user with explicit password hashing
            password_hash = generate_password_hash(password)
            logging.debug(f"Created password hash for user {username}")

            user = User(
                username=username.lower(),
                email=email,
                password_hash=password_hash
            )
            db.session.add(user)
            db.session.commit()
            logging.info(f"Successfully registered user: {username}")

            # Automatically log in the user after registration
            session.clear()  # Clear any existing session
            session['user_id'] = user.id
            session.permanent = True  # Make session persistent
            flash('Registration successful! Welcome to your profile.', 'success')
            return redirect(url_for('profile', user_id=user.id))

        except Exception as e:
            db.session.rollback()
            logging.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        logging.info(f"Login attempt for username: {username}")

        try:
            user = User.query.filter_by(username=username).first()
            logging.debug(f"Found user: {user is not None}")

            if user:
                is_valid = check_password_hash(user.password_hash, password)
                logging.debug(f"Password validation result: {is_valid}")

                if is_valid:
                    session.clear()  # Clear any existing session
                    session['user_id'] = user.id
                    session.permanent = True  # Make session persistent
                    flash('Logged in successfully', 'success')
                    logging.info(f"Successful login for user: {username}")
                    return redirect(url_for('profile', user_id=user.id))
                else:
                    logging.warning(f"Invalid password for user: {username}")

            flash('Invalid username or password')
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Login error: {e}")
            flash('Error during login')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    try:
        user = User.query.get_or_404(user_id)
        # Intentionally vulnerable - allows viewing any user profile
        return render_template('profile.html', user=user)
    except Exception as e:
        logging.error(f"Profile access error: {e}")
        flash('Error accessing profile', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()  # Clear the entire session
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/profile/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    user = User.query.get_or_404(user_id)

    # Intentionally vulnerable - allows editing any user profile
    # Security check removed to create IDOR vulnerability

    if request.method == 'POST':
        user.bio = request.form.get('bio', '').strip()
        user.phone = request.form.get('phone', '').strip()
        user.address = request.form.get('address', '').strip()

        try:
            db.session.commit()
            flash('Profile updated successfully', 'success')
            return redirect(url_for('profile', user_id=user_id))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating profile: {e}")
            flash('Error updating profile', 'error')

    return render_template('edit_profile.html', user=user)
