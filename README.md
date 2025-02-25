# User Profile System

A secure web application for managing user profiles, built with Flask and PostgreSQL.

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
git clone https://github.com/yourusername/user-profile-system.git
cd user-profile-system
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

The application will be available at `http://localhost:5000`

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
gunicorn --bind 0.0.0.0:5000 main:app
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to your branch
5. Create a Pull Request
