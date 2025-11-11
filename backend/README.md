
# Library Management System - Backend Documentation

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Database Schema](#database-schema)
3. [API Documentation](#api-documentation)
4. [Authentication & Authorization](#authentication--authorization)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Troubleshooting](#troubleshooting)
8. [Development Best Practices](#development-best-practices)

## Architecture Overview

The Library Management System follows a clean, domain-driven architecture with strict separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Routes Layer (HTTP Handling)                │
│  ┌─────────────┬─────────────┬─────────────┐    │
│  │ Users       │ Books       │ Fines       │    │
│  │ Borrows     │ Dashboard   │ Auth        │    │
│  └─────────────┴─────────────┴─────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                   Services Layer (Business Logic)               │
│  ┌─────────────┬─────────────┬─────────────┐    │
│  │ User        │ Book        │ Fine        │    │
│  │ Borrow      │ Library     │ Auth        │    │
│  └─────────────┴─────────────┴─────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                   Repository Layer (Data Access)               │
│  ┌─────────────┬─────────────┬─────────────┐    │
│  │ UserRepo    │ BookRepo    │ FineRepo    │    │
│  │ BorrowRepo  │ ViewLogRepo │ LoginRepo   │    │
│  └─────────────┴─────────────┴─────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                   Database Layer (Models & Schema)            │
│  ┌─────────────┬─────────────┬─────────────┐    │
│  │ User        │ Book        │ Fine        │    │
│  │ Borrow      │ ViewLog     │ LoginAttempt │    │
│  └─────────────┴─────────────┴─────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Separation of Concerns**: Each layer has a single responsibility
2. **Dependency Injection**: Services depend on repositories, not directly on database
3. **Factory Pattern**: Repository instances are created through a factory to avoid circular dependencies
4. **Domain-Driven**: Business logic is organized around domain entities

## Database Schema

### Core Entities

#### Users
```sql
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('student', 'librarian', 'admin') DEFAULT 'student',
    status ENUM('active', 'inactive') DEFAULT 'active',
    email_verified BOOLEAN DEFAULT FALSE,
    date_joined DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

#### Books
```sql
CREATE TABLE books (
    book_id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    isbn VARCHAR(20),
    publisher VARCHAR(255),
    year_published INT,
    quantity_total INT DEFAULT 1,
    quantity_available INT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

#### Borrow Records
```sql
CREATE TABLE borrow_records (
    borrow_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    book_id INT NOT NULL,
    borrow_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    due_date DATETIME NOT NULL,
    return_date DATETIME,
    status ENUM('borrowed', 'returned', 'overdue') DEFAULT 'borrowed',
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (book_id) REFERENCES books(book_id)
);
```

#### Fines
```sql
CREATE TABLE fines (
    fine_id INT PRIMARY KEY AUTO_INCREMENT,
    borrow_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    paid_status ENUM('unpaid', 'paid', 'waived') DEFAULT 'unpaid',
    payment_date DATETIME,
    FOREIGN KEY (borrow_id) REFERENCES borrow_records(borrow_id)
);
```

### Relationships

```
Users ──< Borrows ──< Books
  │        │        │
  │        └─< Fines
  │                 │
  └─< Login Attempts
```

## API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication Endpoints

#### Login
```http
POST /auth/login
Content-Type: application/json

Request:
{
    "email": "user@example.com",
    "password": "password123"
}

Response (Success):
{
    "success": true,
    "user": {
        "user_id": 1,
        "full_name": "John Doe",
        "email": "user@example.com",
        "role": "student",
        "permissions": []
    },
    "tokens": {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "expires_at": "2023-12-01T12:00:00Z"
    }
}

Response (Error):
{
    "success": false,
    "error": "Invalid credentials"
}
```

#### Register
```http
POST /auth/register
Content-Type: application/json

Request:
{
    "full_name": "Jane Doe",
    "email": "jane@example.com",
    "password": "password123",
    "role": "student"
}

Response (Success):
{
    "success": true,
    "user": {
        "user_id": 2,
        "full_name": "Jane Doe",
        "email": "jane@example.com",
        "role": "student"
    }
}
```

### Book Endpoints

#### Get All Books
```http
GET /books

Response:
{
    "success": true,
    "books": [
        {
            "book_id": 1,
            "title": "The Great Gatsby",
            "author": "F. Scott Fitzgerald",
            "category": "Fiction",
            "isbn": "9780743273565",
            "publisher": "Scribner",
            "year_published": 1925,
            "quantity_total": 5,
            "quantity_available": 3
        }
    ]
}
```

#### Get Book by ID
```http
GET /books/{book_id}

Response:
{
    "success": true,
    "book": {
        "book_id": 1,
        "title": "The Great Gatsby",
        "author": "F. Scott Fitzgerald",
        "category": "Fiction",
        "isbn": "9780743273565",
        "publisher": "Scribner",
        "year_published": 1925,
        "quantity_total": 5,
        "quantity_available": 3
    }
}
```

#### Create Book
```http
POST /books
Content-Type: application/json
Authorization: Bearer {access_token}

Request:
{
    "title": "New Book",
    "author": "Author Name",
    "category": "Fiction",
    "isbn": "9781234567890",
    "publisher": "Publisher Name",
    "year_published": 2023,
    "quantity": 10
}

Response (Success):
{
    "success": true,
    "message": "Book added successfully",
    "book": {
        "book_id": 123,
        "title": "New Book",
        "author": "Author Name",
        "category": "Fiction",
        "isbn": "9781234567890",
        "publisher": "Publisher Name",
        "year_published": 2023,
        "quantity_total": 10,
        "quantity_available": 10
    }
}
```

### Borrow Endpoints

#### Borrow Book
```http
POST /borrows/borrow
Content-Type: application/json
Authorization: Bearer {access_token}

Request:
{
    "book_id": 1,
    "due_days": 14
}

Response (Success):
{
    "success": true,
    "message": "Book borrowed successfully",
    "borrow": {
        "borrow_id": 456,
        "user_id": 1,
        "book_id": 1,
        "borrow_date": "2023-11-11T10:00:00Z",
        "due_date": "2023-11-25T10:00:00Z",
        "status": "borrowed"
    }
}
```

#### Return Book
```http
POST /borrows/return/{borrow_id}
Content-Type: application/json
Authorization: Bearer {access_token}

Response (Success):
{
    "success": true,
    "message": "Book returned successfully"
}
```

### Fine Endpoints

#### Get User Fines
```http
GET /fines/my-fines
Authorization: Bearer {access_token}

Response:
{
    "success": true,
    "fines": [
        {
            "fine_id": 789,
            "borrow_id": 456,
            "amount": 5.00,
            "paid_status": "unpaid",
            "payment_date": null
        }
    ]
}
```

#### Pay Fine
```http
POST /fines/pay/{fine_id}
Content-Type: application/json
Authorization: Bearer {access_token}

Response (Success):
{
    "success": true,
    "message": "Fine paid successfully"
}
```

## Authentication & Authorization

### JWT Token System
- **Access Token**: Short-lived (1 hour) token for API access
- **Refresh Token**: Long-lived token for obtaining new access tokens
- **Token Structure**: Contains user ID, role, and permissions

### Role-Based Access Control
- **Student**: Can borrow books, view own fines
- **Librarian**: Can manage books, view all borrows and fines
- **Admin**: Full system access

### OAuth/SAML Integration
- **OAuth Providers**: Google, Microsoft, GitHub
- **SAML Providers**: Enterprise SSO support
- **Account Linking**: Users can link multiple authentication methods

## Configuration

### Environment Variables
Create a `.env` file in the backend root:

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=library_system
DB_USER=library_user
DB_PASSWORD=secure_password

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key-here
JWT_ACCESS_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=2592000

# OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback

MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URI=http://localhost:5000/auth/microsoft/callback

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:5000/auth/github/callback

# SAML Configuration
SAML_SP_ENTITY_ID=http://localhost:5000
SAML_SP_CERT=path/to/sp/certificate.pem
SAML_SP_KEY=path/to/sp/private-key.pem

# Application Configuration
FLASK_ENV=development
DEBUG=True
CORS_ORIGINS=http://localhost:3000,http://localhost:3001
```

### Database Setup

1. **MySQL/MariaDB Installation**:
   ```bash
   sudo apt-get install mysql-server
   sudo mysql_secure_installation
   ```

2. **Database Creation**:
   ```sql
   CREATE DATABASE library_system;
   ```

3. **Schema Initialization**:
   ```bash
   python -c "from db.database import init_db; init_db()"
   ```

### Redis Setup (for sessions)
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

## Deployment

### Development Deployment
```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
python server.py
```

### Production Deployment

#### Using Gunicorn
```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 server:app
```

#### Using Docker
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "server:app"]
```

#### Docker Compose
```yaml
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DB_HOST=mysql
      - DB_PORT=3306
      - DB_NAME=library_system
      - DB_USER=library_user
      - DB_PASSWORD=secure_password
    depends_on:
      - mysql
      - redis

  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=rootpassword
      - MYSQL_DATABASE=library_system
      - MYSQL_USER=library_user
      - MYSQL_PASSWORD=secure_password
    volumes:
      - mysql_data:/var/lib/mysql

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

## Troubleshooting

### Common Issues

#### Database Connection Issues
**Problem**: "Error initializing OAuth providers: Working outside of application context"
**Solution**: Ensure Flask app context is properly initialized before importing services

#### Import Errors
**Problem**: "No module named 'python3_saml'"
**Solution**: Install missing dependencies:
```bash
pip install python3-saml
```

#### CORS Issues
**Problem**: "CORS policy: No 'Access-Control-Allow-Origin' header"
**Solution**: Check CORS_ORIGINS configuration in `.env` file

### Debug Mode
Enable debug mode by setting:
```bash
FLASK_ENV=development
DEBUG=True
```

This provides:
- Detailed error messages
- Auto-reload on code changes
- Debug toolbar

## Development Best Practices

### Code Organization
1. **Follow the established layering**:
   - Routes: HTTP handling only
   - Services: Business logic only
   - Repositories: Data access only

2. **Use dependency injection**:
   ```python
   # Good
   repos = get_repositories()
   user = repos['user'].get_by_id(user_id)
   
   # Bad
   from db.repository import user_repository
   user = user_repository.get_by_id(user_id)
   ```

3. **Handle errors gracefully**:
   ```python
   try:
       result = service.some_operation()
   except Exception as e:
       logger.error(f"Operation failed: {str(e)}")
       return None
   ```

### Security Best Practices

1. **Password Security**:
   - Use bcrypt for password hashing
   - Enforce strong password policies
   - Never log plain text passwords

2. **JWT Security**:
   - Use strong secret keys
   - Set appropriate token expiration
   - Implement token refresh mechanism

3. **Input Validation**:
   - Validate all user inputs
   - Use parameterized queries to prevent SQL injection
   - Sanitize data before processing

### Performance Optimization

1. **Database Indexing**:
   ```sql
   CREATE INDEX idx_users_email ON users(email);
   CREATE INDEX idx_borrows_user_id ON borrow_records(user_id);
   CREATE INDEX idx_borrows_status ON borrow_records(status);
   ```

2. **Connection Pooling**:
   - Use connection pooling for database connections
   - Implement proper connection cleanup

3. **Caching**:
   - Cache frequently accessed data
   - Use Redis for session storage
   - Implement query result caching

### Testing

1. **Unit Tests**:
   ```python
   def test_user_creation():
       user = User(full_name="Test", email="test@example.com")
       assert user.full_name == "Test"
       assert user.email == "test@example.com"
   ```

2. **Integration Tests**:
   ```python
   def test_borrow_flow():
       # Create user
       # Create book
       # Borrow book
       # Return book
       # Verify all operations
   ```

3. **API Testing**:
   ```python
   def test_api_endpoints():
       # Test all API endpoints
       # Verify response formats
       # Check error handling
   ```

## Maintenance

### Database Maintenance

1. **Regular Backups**:
   ```bash
   mysqldump -u library_user -p library_system > backup_$(date +%Y%m%d).sql
   ```

2. **Log Rotation**:
   ```bash
   # Rotate logs weekly
   logrotate /etc/logrotate.d/library-system
   ```

3. **Performance Monitoring**:
   - Monitor query execution times
   - Track connection pool usage
   - Monitor memory usage

### Security Maintenance

1. **Token Cleanup**:
   ```python
   # Clean up expired refresh tokens
   def cleanup_expired_tokens():
       # Remove tokens older than 30 days
   ```

2. **Security Updates**:
   - Regularly update dependencies
   - Monitor security advisories
   - Apply security patches promptly

## API Versioning

### Version 1.0.0
Current API version with the following features:
- User authentication and authorization
- Book management (CRUD operations)
- Borrowing system with due date tracking
- Fine management with payment tracking
- Role-based access control
- OAuth/SAML integration support

### Versioning Strategy
- Use semantic versioning (MAJOR.MINOR.PATCH)
- Maintain backward compatibility within major versions
- Document breaking changes in release notes

## Support

For technical support or questions:
- Check the troubleshooting guide first
- Review the API documentation
- Check application logs for error details
- Contact development team with specific error details

## Quick Start Guide

### 1. Setup Database
```bash
# Create database
mysql -u root -p
CREATE DATABASE library_system;
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Initialize Database Schema
```bash
python -c "from db.database import init_db; init_db()"
```

### 5. Run Development Server
```bash
python server.py
```

### 6. Access API
The API will be available at `http://localhost:5000`

## Architecture Decision Log

### Key Changes Made
1. **Centralized Database Models**: All models now in `db/models.py`
2. **Repository Pattern**: Data access through `db/repository.py`
3. **Service Layer**: Business logic in `services/` directory
4. **Route Layer**: HTTP handling in `routes/` directory
5. **Removed Circular Dependencies**: Factory pattern for repository access
6. **Fixed OAuth/SAML Initialization**: Deferred until app context available

### Migration Guide
For existing code using old patterns:

#### Before (Old Pattern)
```python
# Direct database access
from db.database import get_connection
conn = get_connection()
cursor = conn.cursor()
cursor.execute("SELECT * FROM users")
```

#### After (New Pattern)
```python
# Repository pattern
from db.repositories import get_repositories
repos = get_repositories()
users = repos['user'].get_all()
```

### Performance Improvements
- Reduced database connection overhead
- Improved query efficiency
- Better error handling
- Cleaner code organization

## Data Flow Diagrams

### User Authentication Flow
```
Client → Routes/auth.py → AuthService → UserRepository → Database
   ↓         ↓              ↓             ↓           ↓
Login → validate_credentials() → get_by_email() → SELECT → User
   ↓         ↓              ↓             ↓           ↓
Token ← create_tokens() ← update_last_login() ← UPDATE ← User
```

### Book Borrowing Flow
```
Client → Routes/borrows.py → BorrowService → Multiple Repositories → Database
   ↓         ↓                ↓                ↓                    ↓
Borrow → create_borrow() → BookRepo.get_by_id() → SELECT → Book
   ↓         ↓                ↓                ↓                    ↓
         ↓                → BorrowRepo.create() → INSERT → BorrowRecord
   ↓         ↓                ↓                ↓                    ↓
Success ← format_response() ← update_book_quantity() ← UPDATE ← Book
```

### Fine Calculation Flow
```
System → FineService → BorrowRepo → FineRepo → Database
   ↓         ↓            ↓           ↓           ↓
Check → calculate_fine() → get_overdue() → SELECT → BorrowRecord
   ↓         ↓            ↓           ↓           ↓
         ↓            → create() → INSERT → Fine
   ↓         ↓            ↓           ↓           ↓
Notify ← send_notification() ← get_user_fines() ← SELECT → Fine
```

## Monitoring and Logging

### Application Logging
```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Usage in services
logger = logging.getLogger(__name__)
logger.info(f"User {user_id} borrowed book {book_id}")
```

### Performance Monitoring
```python
import time
from functools import wraps

def monitor_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logger.info(f"{func.__name__} executed in {end_time - start_time:.2f}s")
        return result
    return wrapper
```

### Health Check Endpoint
```http
GET /health

Response:
{
    "status": "healthy",
    "timestamp": "2023-11-11T20:00:00Z",
    "database": "connected",
    "redis": "connected"
}
```

## Security Considerations

### Input Validation
```python
from utils.validators import validate_email, validate_password

def validate_user_data(data):
    errors = []
    
    if not validate_email(data.get('email', '')):
        errors.append('Invalid email format')
    
    if not validate_password(data.get('password', '')):
        errors.append('Password does not meet requirements')
    
    return errors
```

### Rate Limiting
```python
from services.rate_limit_service import RateLimitService

rate_limiter = RateLimitService()

@app.before_request
def check_rate_limit():
    client_ip = request.remote_addr
    if not rate_limiter.is_allowed(client_ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429
```

### SQL Injection Prevention
```python
# Good: Using parameterized queries
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# Bad: Direct string interpolation (vulnerable to SQL injection)
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

## Contributing Guidelines

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions small and focused

### Pull Request Process
1. Create a feature branch from main
2. Implement your changes with tests
3. Ensure all tests pass
4. Update documentation as needed
5. Submit a pull request with clear description

### Testing Requirements
```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=backend tests/

# Run specific test file
python -m pytest tests/test_auth.py
```

---

*This documentation covers the complete backend architecture, API endpoints, configuration, deployment, maintenance procedures, and development guidelines for the Library Management System.*