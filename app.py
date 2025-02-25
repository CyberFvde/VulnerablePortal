import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_key_for_demo")

# Configure PostgreSQL database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Import models after db initialization
from models import User

# Initialize database
with app.app_context():
    db.create_all()
    logging.info("Database tables created successfully")

@app.route('/')
def index():
    return render_template('warning.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Logged in successfully')
            return redirect(url_for('profile', user_id=user.id))

        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Intentionally vulnerable IDOR endpoint
    # No authentication check - any user can access any profile
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully')
    return redirect(url_for('login'))