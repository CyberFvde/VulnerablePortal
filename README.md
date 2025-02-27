# User Profile System

An insecure web application for managing user profiles, built with Flask and PostgreSQL.

## Features

- User authentication and authorization
- Profile management system
- PostgreSQL database integration
- Responsive Bootstrap UI
- Secure password handling

## Tech Stack

- Python 3.11
- Flask Framework
- PostgreSQL
- SQLAlchemy ORM
- Bootstrap 5

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL database
- pip package manager

### Installation

1. Clone the repository
```bash
git clone https://github.com/CyberFvde/VulnerablePortal.git
cd VulnerablePortal
```

2. Install dependencies
```bash
pip install flask flask-sqlalchemy psycopg2-binary flask-login flask-wtf email-validator gunicorn
```

3. Configure environment variables
Create a `.env` file with:
```
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
SESSION_SECRET=your_secure_secret_key
```

4. Run the application
```bash
python main.py
```

The application will be available at `http://localhost:5001`

## Project Structure

```
├── app.py              # Main application file
├── main.py            # Entry point
├── models.py          # Database models
├── static/            # Static files
└── templates/         # HTML templates
```

## Database Schema

### Users Table
- id (Primary Key)
- username (Unique)
- email (Unique)
- password_hash
- bio (Optional)
- phone (Optional)
- address (Optional)

## Security Features

- Secure password hashing
- Session management
- Case-insensitive username handling
- PostgreSQL database security

## Deployment

1. Set up a production PostgreSQL database
2. Configure environment variables
3. Use Gunicorn for production server:
```bash
gunicorn --bind 0.0.0.0:5001 main:app
```

## Secure Fix

@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Secure: Ensure the user is authenticated and can only access their own profile
    if 'user_id' not in session or session['user_id'] != user_id:
        flash('Unauthorized access')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)
Instructions to Fix:

Replace the vulnerable profile route in your app.py with the secure version provided above.
This version checks if the logged-in user's ID (stored in the session) matches the user ID in the URL.
If the check fails, it flashes an "Unauthorized access" message and redirects the user to the login page.
This ensures that users can only view their own profiles, preventing unauthorized access.
