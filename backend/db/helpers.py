from db.database import get_connection, init_db
import bcrypt #type: ignore

# USERS 
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

def add_user(full_name, email, password, role="student"):
    hashed = hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (full_name, email, password, role)
        VALUES (%s, %s, %s, %s)
    """, (full_name, email, hashed, role))
    conn.commit()
    cursor.close()
    conn.close()

def get_all_users():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users ORDER BY date_joined DESC")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return users

def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def suspend_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'inactive' WHERE user_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

def activate_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status = 'active' WHERE user_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

def reset_user_password(user_id, new_password):
    hashed = hash_password(new_password)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET password = %s
        WHERE user_id = %s
    """, (hashed, user_id))
    conn.commit()
    cursor.close()
    conn.close()

# BOOKS
def add_book(title, author, category, isbn, publisher, year, quantity):
    if not title or not author or quantity <= 0:
        raise ValueError("Invalid book data. Check title, author, and quantity.")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO books (title, author, category, isbn, publisher, year_published,
                           quantity_total, quantity_available)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (title, author, category, isbn, publisher, year, quantity, quantity))
    conn.commit()
    cursor.close()
    conn.close()

def get_book_by_id(book_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM books WHERE book_id = %s", (book_id,))
    book = cursor.fetchone()
    cursor.close()
    conn.close()
    return book

def adjust_book_quantity(book_id, total_change=0, available_change=0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE books
        SET quantity_total = quantity_total + %s,
            quantity_available = quantity_available + %s
        WHERE book_id = %s
    """, (total_change, available_change, book_id))

    conn.commit()
    cursor.close()
    conn.close()

def filter_books(title=None, author=None, category=None, isbn=None, year=None):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM books WHERE 1=1"
    params = []

    if title:
        query += " AND title LIKE %s"
        params.append(f"%{title}%")
    if author:
        query += " AND author LIKE %s"
        params.append(f"%{author}%")
    if category:
        query += " AND category LIKE %s"
        params.append(f"%{category}%")
    if isbn:
        query += " AND isbn LIKE %s"
        params.append(f"%{isbn}%")
    if year:
        query += " AND year_published = %s"
        params.append(year)

    cursor.execute(query, tuple(params))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results

def list_books():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM books")
    books = cursor.fetchall()
    cursor.close()
    conn.close()
    return books

def delete_book(book_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM books WHERE book_id = %s", (book_id,))
    conn.commit()
    cursor.close()
    conn.close()

# VIEW LOGS
def log_book_view(user_id, book_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO view_log (user_id, book_id, view_date)
        VALUES (%s, %s, NOW())
    """, (user_id, book_id))
    conn.commit()
    cursor.close()
    conn.close()

def get_user_view_history(user_id, limit=10):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT v.view_id, v.book_id, v.view_date, b.title, b.author, b.category
        FROM view_log v
        JOIN books b ON v.book_id = b.book_id
        WHERE v.user_id = %s
        ORDER BY v.view_date DESC
        LIMIT %s
    """, (user_id, limit))
    history = cursor.fetchall()
    cursor.close()
    conn.close()
    return history

def borrow_book(user_id, book_id, due_date):
    conn = get_connection()
    cursor = conn.cursor()
    # Check for existing active borrow
    cursor.execute("""
        SELECT COUNT(*) FROM borrow_records
        WHERE user_id = %s AND book_id = %s AND status = 'borrowed'
    """, (user_id, book_id))
    already_borrowed = cursor.fetchone()[0]
    if already_borrowed > 0:
        cursor.close()
        conn.close()
        raise ValueError("This user already borrowed this book and has not returned it yet.")

    # Check for available copies
    cursor.execute("SELECT quantity_available FROM books WHERE book_id = %s", (book_id,))
    result = cursor.fetchone()
    if not result or result[0] <= 0:
        cursor.close()
        conn.close()
        raise ValueError("Book is not currently available for borrowing.")

    # borrow
    cursor.execute("""
        INSERT INTO borrow_records (user_id, book_id, due_date)
        VALUES (%s, %s, %s)
    """, (user_id, book_id, due_date))

    cursor.execute("""
        UPDATE books
        SET quantity_available = quantity_available - 1
        WHERE book_id = %s
    """, (book_id,))

    conn.commit()
    cursor.close()
    conn.close()

def return_book(borrow_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT book_id FROM borrow_records WHERE borrow_id = %s", (borrow_id,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        conn.close()
        raise ValueError("Invalid borrow_id")

    book_id = row[0]

    cursor.execute("""
        UPDATE borrow_records
        SET status = 'returned', return_date = NOW()
        WHERE borrow_id = %s
    """, (borrow_id,))

    cursor.execute("""
        UPDATE books
        SET quantity_available = quantity_available + 1
        WHERE book_id = %s
    """, (book_id,))

    conn.commit()
    cursor.close()
    conn.close()

def get_active_borrows(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT br.borrow_id, br.book_id, b.title, b.author, br.borrow_date, br.due_date, br.status
        FROM borrow_records br
        JOIN books b ON br.book_id = b.book_id
        WHERE br.user_id = %s AND br.status = 'borrowed'
        ORDER BY br.borrow_date DESC
    """, (user_id,))
    borrows = cursor.fetchall()
    cursor.close()
    conn.close()
    return borrows

def get_overdue_borrows():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT br.borrow_id, u.full_name, b.title, br.due_date
        FROM borrow_records br
        JOIN users u ON br.user_id = u.user_id
        JOIN books b ON br.book_id = b.book_id
        WHERE br.status = 'borrowed' AND br.due_date < NOW()
    """)
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results

def get_all_borrows(status=None):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT br.borrow_id, u.full_name AS user_name, u.email,
               b.title AS book_title, b.author,
               br.borrow_date, br.due_date, br.return_date, br.status
        FROM borrow_records br
        JOIN users u ON br.user_id = u.user_id
        JOIN books b ON br.book_id = b.book_id
    """
    params = ()

    if status:
        query += " WHERE br.status = %s"
        params = (status,)

    query += " ORDER BY br.borrow_date DESC"

    cursor.execute(query, params)
    records = cursor.fetchall()
    cursor.close()
    conn.close()
    return records

# FINES
def add_fine(borrow_id, amount):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO fines (borrow_id, amount, paid_status)
        VALUES (%s, %s, 'unpaid')
    """, (borrow_id, amount))
    conn.commit()
    cursor.close()
    conn.close()

def pay_fine(fine_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE fines
        SET paid_status = 'paid', payment_date = NOW()
        WHERE fine_id = %s
    """, (fine_id,))
    conn.commit()
    cursor.close()
    conn.close()

def get_user_fines(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT f.fine_id, f.amount, f.paid_status, f.payment_date, b.title
        FROM fines f
        JOIN borrow_records br ON f.borrow_id = br.borrow_id
        JOIN books b ON br.book_id = b.book_id
        WHERE br.user_id = %s
        ORDER BY f.paid_status, f.payment_date DESC
    """, (user_id,))
    fines = cursor.fetchall()
    cursor.close()
    conn.close()
    return fines

def get_all_fines(paid_status=None):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT f.fine_id, u.full_name AS user_name, b.title AS book_title,
               f.amount, f.paid_status, f.payment_date, br.borrow_id
        FROM fines f
        JOIN borrow_records br ON f.borrow_id = br.borrow_id
        JOIN users u ON br.user_id = u.user_id
        JOIN books b ON br.book_id = b.book_id
    """
    params = ()

    if paid_status:
        query += " WHERE f.paid_status = %s"
        params = (paid_status,)

    query += " ORDER BY f.payment_date DESC, f.paid_status ASC"

    cursor.execute(query, params)
    records = cursor.fetchall()
    cursor.close()
    conn.close()
    return records

# LIBRARY STATS FOR ADMIN
def get_library_stats():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT
            (SELECT COUNT(*) FROM users WHERE status='active') AS active_users,
            (SELECT COUNT(*) FROM books) AS total_books,
            (SELECT COUNT(*) FROM borrow_records WHERE status='borrowed') AS active_borrows,
            (SELECT COUNT(*) FROM fines WHERE paid_status='unpaid') AS unpaid_fines
    """)
    stats = cursor.fetchone()
    cursor.close()
    conn.close()
    return stats

# Initialize the database
try:
    init_db(True)
except Exception as e:
    print(f"Database initialization error: {e}")
