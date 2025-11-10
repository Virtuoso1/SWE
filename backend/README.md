# Flask Authentication System

A robust Flask backend implementation for user authentication featuring secure session management, MySQL database integration, and comprehensive security measures.

## Features

- **Secure Authentication**: Password hashing with bcrypt, protection against timing attacks
- **Session Management**: Secure Flask-Session implementation with configurable timeouts
- **Rate Limiting**: Login attempt rate limiting to prevent brute force attacks
- **CSRF Protection**: Cross-Site Request Forgery protection with secure tokens
- **Security Headers**: Comprehensive security headers for production deployment
- **Error Handling**: Structured error responses with appropriate HTTP status codes
- **Logging**: Comprehensive logging for security monitoring and debugging
- **Environment Configuration**: Flexible configuration for development, testing, and production

## Project Structure

```
backend/
├── config.py              # Configuration management
├── server.py              # Main Flask application
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── routes/
│   └── auth.py           # Authentication routes
├── services/
│   └── auth_service.py   # Authentication business logic
├── utils/
│   ├── validators.py     # Input validation utilities
│   └── security.py       # Security utilities
└── db/
    ├── database.py       # Database connection management
    ├── helpers.py        # Database helper functions
    └── schema.sql        # Database schema
```

## Installation

1. **Clone the repository and navigate to the backend directory**

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Set up the database**
   - Create a MySQL database
   - Update database credentials in `.env`
   - The application will automatically initialize the database schema on startup

## Configuration

### Environment Variables

Key environment variables in `.env`:

- `FLASK_ENV`: Environment (development/testing/production)
- `SECRET_KEY`: Flask secret key for session security
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: Database connection
- `LOGIN_ATTEMPT_LIMIT`: Maximum failed login attempts (default: 5)
- `LOGIN_ATTEMPT_WINDOW`: Time window for rate limiting in minutes (default: 15)
- `SESSION_MAX_AGE`: Session timeout in seconds (default: 3600)

### Security Configuration

The system includes multiple security layers:

1. **Password Security**: bcrypt hashing with salt
2. **Session Security**: Signed sessions with secure cookies
3. **CSRF Protection**: Token-based CSRF protection
4. **Rate Limiting**: Login attempt rate limiting
5. **Security Headers**: Comprehensive HTTP security headers

## API Endpoints

### Authentication Endpoints

#### POST /auth/login
Authenticate user and create session.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "userpassword"
}
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "user_id": 1,
    "full_name": "John Doe",
    "email": "user@example.com",
    "role": "student"
  },
  "csrf_token": "random_csrf_token"
}
```

**Error Responses:**
- `400` - Missing or invalid input
- `401` - Invalid credentials
- `429` - Rate limit exceeded
- `500` - Internal server error

#### POST /auth/logout
Logout user and clear session.

**Success Response (200):**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

#### GET /auth/check
Check if user is authenticated.

**Success Response (200):**
```json
{
  "success": true,
  "authenticated": true,
  "user": {
    "user_id": 1,
    "full_name": "John Doe",
    "email": "user@example.com",
    "role": "student"
  }
}
```

### Utility Endpoints

#### GET /
API information and available endpoints.

#### GET /health
Health check endpoint with database status.

## Security Features

### Password Security
- bcrypt hashing with automatic salt generation
- Constant-time password comparison to prevent timing attacks
- Password length validation (minimum 8 characters)

### Session Management
- Server-side session storage with Flask-Session
- Secure session cookies with HttpOnly, Secure, and SameSite attributes
- Configurable session timeout
- Session signing to prevent tampering

### Rate Limiting
- Login attempt rate limiting per email address
- Configurable attempt limits and time windows
- Database-backed rate limiting for persistence

### CSRF Protection
- Per-session CSRF tokens
- Token validation for state-changing operations
- Secure token generation using secrets module

### Input Validation
- Email format validation with regex
- Password strength validation
- Input sanitization to prevent injection attacks
- Type checking and length validation

### Security Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HTTPS only)
- Content-Security-Policy

### Logging and Monitoring
- Comprehensive request/response logging
- Login attempt logging with IP addresses
- Error logging with stack traces
- Security event logging

## Database Schema

The system uses the following key tables:

- `users`: User accounts with roles and status
- `login_attempts`: Login attempt tracking for security
- `view_log`: Book viewing history
- `books`: Library book catalog
- `borrow_records`: Book borrowing records
- `fines`: Fine management

## Development

### Running the Development Server
```bash
python server.py
```

### Database Initialization
The database is automatically initialized on startup. To manually initialize:
```python
from db.database import init_db
init_db()
```

### Testing
```bash
pytest
```

## Production Deployment

### Security Considerations
1. Set `FLASK_ENV=production`
2. Use a strong, randomly generated `SECRET_KEY`
3. Configure HTTPS with valid SSL certificates
4. Set up proper database credentials
5. Configure reverse proxy (nginx/Apache)
6. Set up monitoring and alerting

### Environment Setup
1. Copy `.env.example` to `.env`
2. Configure production values
3. Set up MySQL database
4. Install dependencies: `pip install -r requirements.txt`
5. Run with production server: `gunicorn server:app`

## Error Handling

The system provides structured error responses:

```json
{
  "success": false,
  "message": "Error description",
  "error_code": "ERROR_CODE"
}
```

Common error codes:
- `INVALID_REQUEST`: Malformed request
- `MISSING_EMAIL`/`MISSING_PASSWORD`: Missing required fields
- `INVALID_EMAIL`/`INVALID_PASSWORD`: Invalid input format
- `INVALID_CREDENTIALS`: Authentication failed
- `RATE_LIMIT_EXCEEDED`: Too many attempts
- `INTERNAL_ERROR`: Server error

## Contributing

1. Follow PEP 8 style guidelines
2. Add tests for new features
3. Update documentation
4. Ensure security best practices
5. Test thoroughly before deployment

## License

This project is licensed under the MIT License.