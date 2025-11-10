CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('student','librarian','admin') DEFAULT 'student',
    status ENUM('active','inactive') DEFAULT 'active',
    date_joined DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS books (
    book_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    author VARCHAR(100) NOT NULL,
    category VARCHAR(50),
    isbn VARCHAR(30) UNIQUE,
    publisher VARCHAR(100),
    year_published YEAR,
    quantity_total INT DEFAULT 1,
    quantity_available INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS borrow_records (
    borrow_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    book_id INT,
    borrow_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    due_date DATETIME,
    return_date DATETIME,
    status ENUM('borrowed','returned','overdue') DEFAULT 'borrowed',
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (book_id) REFERENCES books(book_id)
);

CREATE TABLE IF NOT EXISTS fines (
    fine_id INT AUTO_INCREMENT PRIMARY KEY,
    borrow_id INT,
    amount DECIMAL(10,2),
    paid_status ENUM('unpaid','paid') DEFAULT 'unpaid',
    payment_date DATETIME
);
CREATE TABLE IF NOT EXISTS view_log (
    view_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    book_id INT,
    view_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (book_id) REFERENCES books(book_id)
);