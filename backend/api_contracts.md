# API Contracts Documentation

This document outlines the existing API contracts that must be preserved during the refactoring process.

## Authentication Endpoints

### POST /auth/login
**Request:**
```json
{
    "email": "user@example.com",
    "password": "userpassword"
}
```

**Response (Success):**
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

**Response (Error):**
```json
{
    "success": false,
    "message": "Error description",
    "error_code": "ERROR_CODE"
}
```

### POST /auth/logout
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "Logout successful"
}
```

### GET /auth/check
**Request:**
No request body required

**Response (Success - Authenticated):**
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

**Response (Success - Not Authenticated):**
```json
{
    "success": true,
    "authenticated": false
}
```

### POST /auth/register
**Request:**
```json
{
    "email": "user@example.com",
    "password": "userpassword",
    "full_name": "John Doe"
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Registration successful",
    "user": {
        "user_id": 1,
        "full_name": "John Doe",
        "email": "user@example.com",
        "role": "student"
    }
}
```

## Book Endpoints

### GET /books
**Request:**
No request body required

**Response (Success):**
```json
[
    {
        "book_id": 1,
        "title": "Book Title",
        "author": "Author Name",
        "category": "Fiction",
        "isbn": "1234567890",
        "publisher": "Publisher",
        "year_published": 2023,
        "quantity_total": 5,
        "quantity_available": 3
    }
]
```

### GET /books/{book_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "book_id": 1,
    "title": "Book Title",
    "author": "Author Name",
    "category": "Fiction",
    "isbn": "1234567890",
    "publisher": "Publisher",
    "year_published": 2023,
    "quantity_total": 5,
    "quantity_available": 3
}
```

**Response (Error - Not Found):**
```json
{
    "error": "Book not found"
}
```

### POST /books
**Request:**
```json
{
    "title": "Book Title",
    "author": "Author Name",
    "category": "Fiction",
    "isbn": "1234567890",
    "publisher": "Publisher",
    "year": 2023,
    "quantity": 5
}
```

**Response (Success):**
```json
{
    "message": "Book added successfully"
}
```

### PUT /books/{book_id}
**Request:**
```json
{
    "title": "Updated Title",
    "author": "Updated Author",
    "category": "Updated Category",
    "isbn": "Updated ISBN",
    "publisher": "Updated Publisher",
    "year": 2024,
    "quantity_total": 10,
    "quantity_available": 8
}
```

**Response (Success):**
```json
{
    "message": "Book updated successfully"
}
```

### DELETE /books/{book_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "message": "Book deleted successfully"
}
```

### GET /books/filter
**Request:**
Query Parameters:
- title: Filter by title (partial match)
- author: Filter by author (partial match)
- category: Filter by category (partial match)
- isbn: Filter by ISBN (partial match)
- year: Filter by publication year (exact match)

**Response (Success):**
```json
[
    {
        "book_id": 1,
        "title": "Book Title",
        "author": "Author Name",
        "category": "Fiction",
        "isbn": "1234567890",
        "publisher": "Publisher",
        "year_published": 2023,
        "quantity_total": 5,
        "quantity_available": 3
    }
]
```

### POST /books/{book_id}/view
**Request:**
No request body required

**Response (Success):**
```json
{
    "message": "View logged successfully"
}
```

### GET /books/{book_id}/availability
**Request:**
No request body required

**Response (Success):**
```json
{
    "book_id": 1,
    "available": true
}
```

## Borrow Endpoints

### POST /borrows/borrow
**Request:**
```json
{
    "book_id": 1,
    "due_days": 14
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Book borrowed successfully",
    "borrow": {
        "borrow_id": 1,
        "user_id": 1,
        "book_id": 1,
        "borrow_date": "2023-01-01T10:00:00Z",
        "due_date": "2023-01-15T10:00:00Z",
        "status": "borrowed"
    }
}
```

### POST /borrows/return/{borrow_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "Book returned successfully"
}
```

### GET /borrows/my-borrows
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "borrows": [
        {
            "borrow_id": 1,
            "user_id": 1,
            "book_id": 1,
            "borrow_date": "2023-01-01T10:00:00Z",
            "due_date": "2023-01-15T10:00:00Z",
            "status": "borrowed"
        }
    ]
}
```

### GET /borrows/all
**Request:**
Query Parameters:
- status: Filter by status ('borrowed', 'returned', 'overdue')

**Response (Success):**
```json
{
    "success": true,
    "borrows": [
        {
            "borrow_id": 1,
            "user_id": 1,
            "book_id": 1,
            "borrow_date": "2023-01-01T10:00:00Z",
            "due_date": "2023-01-15T10:00:00Z",
            "status": "borrowed"
        }
    ]
}
```

### GET /borrows/overdue
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "borrows": [
        {
            "borrow_id": 1,
            "user_id": 1,
            "book_id": 1,
            "borrow_date": "2023-01-01T10:00:00Z",
            "due_date": "2023-01-15T10:00:00Z",
            "status": "borrowed"
        }
    ]
}
```

### GET /borrows/{borrow_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "borrow": {
        "borrow_id": 1,
        "user_id": 1,
        "book_id": 1,
        "borrow_date": "2023-01-01T10:00:00Z",
        "due_date": "2023-01-15T10:00:00Z",
        "status": "borrowed"
    }
}
```

### POST /borrows/extend/{borrow_id}
**Request:**
```json
{
    "additional_days": 7
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Due date extended successfully"
}
```

### GET /borrows/statistics
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "statistics": {
        "total_borrows": 100,
        "active_borrows": 25,
        "returned_borrows": 75,
        "overdue_borrows": 5
    }
}
```

## Fine Endpoints

### GET /fines/my-fines
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "fines": [
        {
            "fine_id": 1,
            "borrow_id": 1,
            "amount": 10.50,
            "paid_status": "unpaid",
            "payment_date": null
        }
    ]
}
```

### GET /fines/all
**Request:**
Query Parameters:
- paid_status: Filter by paid status ('paid', 'unpaid')

**Response (Success):**
```json
{
    "success": true,
    "fines": [
        {
            "fine_id": 1,
            "borrow_id": 1,
            "amount": 10.50,
            "paid_status": "unpaid",
            "payment_date": null
        }
    ]
}
```

### GET /fines/{fine_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "fine": {
        "fine_id": 1,
        "borrow_id": 1,
        "amount": 10.50,
        "paid_status": "unpaid",
        "payment_date": null
    }
}
```

### POST /fines/pay/{fine_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "Fine paid successfully"
}
```

### POST /fines/create
**Request:**
```json
{
    "borrow_id": 1,
    "amount": 10.50
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Fine created successfully",
    "fine": {
        "fine_id": 1,
        "borrow_id": 1,
        "amount": 10.50,
        "paid_status": "unpaid"
    }
}
```

### POST /fines/waive/{fine_id}
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "Fine waived successfully"
}
```

### PUT /fines/{fine_id}
**Request:**
```json
{
    "amount": 15.75
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Fine updated successfully"
}
```

### POST /fines/calculate-overdue
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "Created 5 overdue fines",
    "fines_created": 5
}
```

### GET /fines/statistics
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "statistics": {
        "total_fines": 50,
        "paid_fines": 30,
        "unpaid_fines": 20,
        "total_amount": 525.00,
        "paid_amount": 315.00,
        "unpaid_amount": 210.00
    }
}
```

## User Endpoints

### GET /users/profile
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "user": {
        "user_id": 1,
        "full_name": "John Doe",
        "email": "user@example.com",
        "role": "student",
        "status": "active",
        "date_joined": "2023-01-01T10:00:00Z"
    }
}
```

### PUT /users/profile
**Request:**
```json
{
    "full_name": "Updated Name",
    "email": "updated@example.com"
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Profile updated successfully"
}
```

### POST /users/change-password
**Request:**
```json
{
    "current_password": "oldpassword",
    "new_password": "newpassword"
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Password changed successfully"
}
```

### GET /users/all
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "users": [
        {
            "user_id": 1,
            "full_name": "John Doe",
            "email": "user@example.com",
            "role": "student",
            "status": "active",
            "date_joined": "2023-01-01T10:00:00Z"
        }
    ]
}
```

### POST /users/{user_id}/suspend
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "User suspended successfully"
}
```

### POST /users/{user_id}/activate
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "message": "User activated successfully"
}
```

### POST /users/{user_id}/reset-password
**Request:**
```json
{
    "new_password": "newpassword"
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Password reset successfully"
}
```

## Dashboard Endpoints

### GET /dashboard/statistics
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "statistics": {
        "active_users": 100,
        "total_books": 500,
        "active_borrows": 25,
        "unpaid_fines": 20,
        "users": {
            "total_users": 120,
            "active_users": 100,
            "inactive_users": 20,
            "students": 100,
            "librarians": 15,
            "admins": 5
        },
        "books": {
            "total_books": 500,
            "available_books": 450,
            "borrowed_books": 50,
            "total_copies": 1200,
            "available_copies": 950
        },
        "borrows": {
            "total_borrows": 1000,
            "active_borrows": 25,
            "returned_borrows": 975,
            "overdue_borrows": 5
        },
        "fines": {
            "total_fines": 50,
            "paid_fines": 30,
            "unpaid_fines": 20,
            "total_amount": 525.00,
            "paid_amount": 315.00,
            "unpaid_amount": 210.00
        }
    }
}
```

### GET /dashboard/data
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "dashboard": {
        "statistics": { ... },
        "recent_activity": {
            "recent_borrows": [ ... ],
            "recent_fines": [ ... ],
            "overdue_books": [ ... ]
        }
    }
}
```

### GET /dashboard/health
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "health": {
        "status": "healthy",
        "database": "connected",
        "timestamp": "2023-01-01T10:00:00Z",
        "statistics": { ... }
    }
}
```

### GET /dashboard/user-summary
**Request:**
No request body required

**Response (Success):**
```json
{
    "success": true,
    "summary": {
        "user_id": 1,
        "role": "student",
        "active_borrows_count": 2,
        "unpaid_fines_count": 1,
        "total_unpaid_amount": 10.50,
        "recent_borrows": [ ... ],
        "recent_fines": [ ... ],
        "recent_views": [ ... ]
    }
}
```

### GET /dashboard/borrow-stats
**Request:**
Query Parameters:
- period: Time period ('day', 'week', 'month', 'year')

**Response (Success):**
```json
{
    "success": true,
    "statistics": {
        "total_borrows": 1000,
        "active_borrows": 25,
        "returned_borrows": 975,
        "overdue_borrows": 5,
        "period": "month"
    }
}
```

### GET /dashboard/fine-stats
**Request:**
Query Parameters:
- period: Time period ('day', 'week', 'month', 'year')

**Response (Success):**
```json
{
    "success": true,
    "statistics": {
        "total_fines": 50,
        "paid_fines": 30,
        "unpaid_fines": 20,
        "total_amount": 525.00,
        "paid_amount": 315.00,
        "unpaid_amount": 210.00,
        "period": "month"
    }
}
```

## Legacy Fines Module Endpoints

### GET /fine?user_id={user_id}
**Request:**
Query Parameters:
- user_id: ID of the user

**Response (Success):**
```json
[
    {
        "fine_id": 1,
        "amount": 10.50,
        "paid_status": "unpaid",
        "payment_date": null
    }
]
```

### POST /pay
**Request:**
```json
{
    "fine_id": 1
}
```

**Response (Success):**
```json
{
    "message": "Fine marked as paid successfully"
}
```

## System Endpoints

### GET /
**Request:**
No request body required

**Response (Success):**
```json
{
    "message": "Library API is running",
    "version": "v1",
    "endpoints": {
        "auth": "/auth/login",
        "books": "/books",
        "health": "/health"
    }
}
```

### GET /health
**Request:**
No request body required

**Response (Success):**
```json
{
    "status": "healthy",
    "database": "connected",
    "version": "v1"
}
```

## Error Response Format

All endpoints should return errors in the following format:

```json
{
    "success": false,
    "message": "Error description",
    "error_code": "ERROR_CODE"
}
```

Common error codes:
- `INVALID_REQUEST`: Invalid request format
- `MISSING_EMAIL`: Email is required
- `INVALID_EMAIL`: Invalid email format
- `MISSING_PASSWORD`: Password is required
- `INVALID_PASSWORD`: Invalid password
- `RATE_LIMIT_EXCEEDED`: Too many login attempts
- `INVALID_CREDENTIALS`: Invalid email or password
- `REGISTRATION_FAILED`: Registration failed
- `NOT_FOUND`: Resource not found
- `INTERNAL_ERROR`: Internal server error
- `METHOD_NOT_ALLOWED`: Method not allowed
- `LOGOUT_ERROR`: Error during logout
- `AUTH_CHECK_ERROR`: Error checking authentication
- `ACCESS_DENIED`: Access denied (insufficient permissions)

## Status Codes

- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `405`: Method Not Allowed
- `429`: Too Many Requests
- `500`: Internal Server Error