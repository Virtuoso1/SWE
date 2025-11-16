# 📚 Smart-Lib — Hybrid Library Management System

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)

Smart-Lib is a **comprehensive Library Management System (LMS)** built to automate and streamline library operations. It supports full management of books, users, borrowing activities, fines, reporting, and secure authentication — providing both librarians and members with an efficient digital experience.

This hybrid system reduces paperwork, minimizes human error, improves accessibility, and enhances productivity across all library workflows.

---

## 🚀 Features

### 📘 **Library Management**

* Book cataloging & classification
* Book inventory tracking
* Advanced search & filtering
* Borrowing & return workflows
* Fine calculation & management

### 👥 **User & Member Management**

* Member registration
* Profile updates
* Borrowing history
* Role-based access (Admin / Librarian / Member)

### 🔐 **Security**

* JWT authentication
* Password hashing with bcrypt
* OTP verification (pyotp)
* Device fingerprinting
* Rate limiting
* Audit logging
* OAuth / SAML login options

### ⚙️ **Admin Tools**

* User management
* Inventory reports
* Analytics & monitoring (Prometheus, StatsD)
* System logs

### 🧪 **Testing**

* Full pytest support
* Coverage reports
* Mocking & factories
* HTML and JSON test reports

---

## 🧱 System Architecture

Smart-Lib follows a **Hybrid architecture**:

```
Frontend (React / Web)
      |
Flask Backend API (REST)
      |
MySQL Database
      |
Redis (Sessions / Caching)
```

* **Backend:** Flask (REST API)
* **Database:** MySQL using SQLAlchemy ORM
* **Sessions / Cache:** Redis (optional)
* **Auth:** JWT, OTP, OAuth, SAML
* **Deployment:** Gunicorn + Production WSGI
* **Security Tools:** bcrypt, cryptography, flask-limiter
* **Monitoring:** Prometheus, StatsD

### Module Flow Diagram

```
[Routes] ---> [Controllers] ---> [Services] ---> [Database / Redis]
```

* **Routes:** Expose API endpoints
* **Controllers:** Process requests & validation
* **Services:** Business logic, auth, rate-limiting, auditing
* **Database / Redis:** Persistent and session storage

---

## 🛠️ Tech Stack

### **Backend**

* Flask
* SQLAlchemy
* MySQL Connector (`mysql-connector-python`)
* Redis
* Authlib
* PyOTP
* PyJWT
* Flask-Limiter

### **Testing & Development**

* pytest, pytest-flask, pytest-cov
* factory-boy, black, flake8

### **Production**

* gunicorn
* Prometheus client
* statsd

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/Smart-Lib.git
cd Smart-Lib
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔧 Configuration

Create a `.env` file in the project root:

```env
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-here-change-in-production
PORT=5000

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=library_db

# Security Configuration
LOGIN_ATTEMPT_LIMIT=5
LOGIN_ATTEMPT_WINDOW=15
PASSWORD_MIN_LENGTH=8
SESSION_MAX_AGE=3600

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=app.log

# API Configuration
API_VERSION=v1

# Rate Limiting
RATELIMIT_STORAGE_URL=memory://
RATELIMIT_DEFAULT=200 per day, 50 per hour
```

---

## 🗄️ Database Setup

### 1. Create MySQL database

```sql
CREATE DATABASE library_db;
```

### 2. Initialize database & enterprise tables

```bash
python backend/db/enterprise_init.py
```

> Ensure your `.env` database credentials match the created database.

---

## ▶️ Running the Server

### Development

```bash
flask run
```

### Production (Gunicorn)

```bash
gunicorn -w 4 backend.server:app
```

---

## 🔗 API Endpoints

| Endpoint               | Method | Description                         |
| ---------------------- | ------ | ----------------------------------- |
| `/auth/login`          | POST   | Login user & return JWT             |
| `/auth/register`       | POST   | Register new user                   |
| `/books`               | GET    | List all books                      |
| `/books`               | POST   | Add a new book (Admin/Librarian)    |
| `/books/<id>`          | GET    | Get book details                    |
| `/books/<id>`          | PUT    | Edit book details (Admin/Librarian) |
| `/books/<id>`          | DELETE | Delete book (Admin/Librarian)       |
| `/borrows`             | POST   | Borrow a book                       |
| `/borrows/<id>/return` | PUT    | Return a borrowed book              |
| `/fines`               | GET    | List fines                          |
| `/dashboard`           | GET    | Admin/Librarian dashboard data      |
| `/health`              | GET    | Server health check                 |

> All endpoints require JWT authentication unless noted otherwise.

---

## 🖥️ Frontend Integration

* Frontend built with React
* Uses **Context API** for auth state management
* Connects to backend via `/auth`, `/books`, `/borrows` REST endpoints
* CORS enabled for `http://localhost:3000`
* Protected routes implemented via `PrivateRoute` component

---

## 🧪 Running Tests

```bash
pytest --cov --html=report.html --json-report
coverage html
```

---

## 📊 Monitoring & Logging

Smart-Lib includes:

* Prometheus metrics endpoints
* StatsD metrics
* Audit logging
* Request tracking & rate limiting

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Commit changes
4. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License**.
