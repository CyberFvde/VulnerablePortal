from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configure logging to help with debugging
logging.basicConfig(level=logging.DEBUG)

# Base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with our base class
db = SQLAlchemy(model_class=Base)
# Create Flask application instance
app = Flask(__name__)

# Set up application secret key for session management
# If no environment variable is set, generate a random key (not recommended for production)
if not os.environ.get("SESSION_SECRET"):
    logging.warning("SESSION_SECRET not set! Using a temporary secret key.")
    app.secret_key = os.urandom(24)
else:
    app.secret_key = os.environ.get("SESSION_SECRET")
    logging.info("Session secret key configured successfully")

# Configure session settings
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # Set session timeout to 30 minutes
app.config['SESSION_COOKIE_SECURE'] = False  # Allow cookies over non-HTTPS connections (for development)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies (security best practice)

# Configure database connection settings
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")  # Get database URL from environment
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Disable modification tracking to improve performance
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,  # Recycle connections after 5 minutes to prevent them from going stale
    "pool_pre_ping": True,  # Test connections before using them to detect disconnections
}

# Initialize the database with our app
db.init_app(app)

# Import models after db initialization to avoid circular imports
from models import User

# Create all database tables based on model definitions
with app.app_context():
    db.create_all()
    logging.info("Database tables created successfully")

# Decorator to require login for protected routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # Check if user is logged in via session
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for landing page
@app.route('/')
def index():
    return render_template('warning.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract and clean form data
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip()

        # Validate all required fields are present
        if not username or not password or not email:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))

        # Validate username length
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return redirect(url_for('register'))

        # Validate password length
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))

        # Check if username already exists (case-insensitive check)
        if User.query.filter_by(username=username.lower()).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        # Check if email already exists (case-insensitive check)
        if User.query.filter_by(email=email.lower()).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        try:
            # Hash the password for secure storage
            password_hash = generate_password_hash(password)
            logging.debug(f"Created password hash for user {username}")

            # Create new user object
            user = User(
                username=username.lower(),
                email=email,
                password_hash=password_hash
            )
            # Add user to database and commit changes
            db.session.add(user)
            db.session.commit()
            logging.info(f"Successfully registered user: {username}")

            # Automatically log in the new user
            session.clear()  # Clear any existing session data
            session['user_id'] = user.id  # Store user ID in session
            session.permanent = True  # Make session persist beyond browser close
            flash('Registration successful! Welcome to your profile.', 'success')
            return redirect(url_for('profile', user_id=user.id))

        except Exception as e:
            # Roll back transaction in case of error
            db.session.rollback()
            logging.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    # For GET requests, display the registration form
    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Extract and normalize login credentials
        username = request.form['username'].strip().lower()
        password = request.form['password']

        logging.info(f"Login attempt for username: {username}")

        try:
            # Look up user by username
            user = User.query.filter_by(username=username).first()
            logging.debug(f"Found user: {user is not None}")

            if user:
                # Verify password hash matches
                is_valid = check_password_hash(user.password_hash, password)
                logging.debug(f"Password validation result: {is_valid}")

                if is_valid:
                    # Set up user session
                    session.clear()  # Clear any existing session
                    session['user_id'] = user.id  # Store user ID in session
                    session.permanent = True  # Make session persistent
                    flash('Logged in successfully')
                    logging.info(f"Successful login for user: {username}")
                    return redirect(url_for('profile', user_id=user.id))
                else:
                    logging.warning(f"Invalid password for user: {username}")

            # Don't reveal which part of the credentials was wrong (security best practice)
            flash('Invalid username or password')
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Login error: {e}")
            flash('Error during login')
            return redirect(url_for('login'))

    # For GET requests, display the login form
    return render_template('login.html')

# User profile route - protected by login_required
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    try:
        # Fetch user by ID or return 404 if not found
        user = User.query.get_or_404(user_id)
        # Ensure users can only view their own profiles
        if session.get('user_id') != user_id:
            flash('You can only view your own profile', 'error')
            return redirect(url_for('profile', user_id=session['user_id']))
        return render_template('profile.html', user=user)
    except Exception as e:
        logging.error(f"Profile access error: {e}")
        flash('Error accessing profile', 'error')
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Remove all session data
    flash('Logged out successfully')
    return redirect(url_for('login'))

# Profile editing route - protected by login_required
@app.route('/profile/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    # Fetch user by ID or return 404 if not found
    user = User.query.get_or_404(user_id)

    # Ensure users can only edit their own profile
    if session['user_id'] != user_id:
        flash('You can only edit your own profile')
        return redirect(url_for('profile', user_id=user_id))

    if request.method == 'POST':
        # Update user profile data from form
        user.bio = request.form.get('bio', '').strip()
        user.phone = request.form.get('phone', '').strip()
        user.address = request.form.get('address', '').strip()

        try:
            # Save changes to database
            db.session.commit()
            flash('Profile updated successfully')
            return redirect(url_for('profile', user_id=user_id))
        except Exception as e:
            # Roll back transaction in case of error
            db.session.rollback()
            logging.error(f"Error updating profile: {e}")
            flash('Error updating profile')

    # For GET requests, display the profile editing form
    return render_template('edit_profile.html', user=user)
