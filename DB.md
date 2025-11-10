Install the following dependencies
    pip install mysql-connector-python bcrypt python-dotenv

Update the env file in backend/db/.env with your database details.

The database and tables are created when you first use a helper function

Use this import at the beginning of backend files to import database function 
    from db.helpers import *

==================
FUNCTION OVERVIEW
==================
USERS
add_user(full_name, email, password, role="student")
	Adds a new user to the system with a securely hashed password.

get_all_users()
	Returns a list of all users in the database.

get_user_by_email(email)
	Retrieves a user record (used for authentication).

suspend_user(user_id)
	Sets a user’s status to inactive (used for suspensions).

activate_user(user_id)
	Sets a user’s status back to active.

delete_user(user_id)
	Permanently deletes a user record from the database.

reset_user_password(user_id, new_password)
	Resets a user’s password (hashed) — used by admin controls.

hash_password(password)
	Hashes plain text password using bcrypt (internal use).

verify_password(password, hashed_password)
	Verifies a password against its hashed version.

BOOKS
add_book(title, author, category, isbn, publisher, year, quantity)
	Adds a new book to the library with total and available copies.

list_books()
	Returns all books in the system.

delete_book(book_id)
	Deletes a book from the database.

get_book_by_id(book_id)
	Retrieves details of a specific book by ID.

adjust_book_quantity(book_id, total_change=0, available_change=0)
	Manually updates total and available book quantities (e.g. lost/damaged/restocked).

filter_books(title=None, author=None, category=None, isbn=None, year=None)
	Searches and filters books dynamically by one or more fields.

BORROW RECORDS
borrow_book(user_id, book_id, due_date)
	Records a new borrowing transaction; validates duplicates and availability.

return_book(borrow_id)
	Marks a borrowed book as returned and restores its available quantity.

get_active_borrows(user_id)
	Lists all active borrowings for a specific user.

get_overdue_borrows()
	Returns all borrow records where the due date has passed.

get_all_borrows(status=None)
	Returns all borrow records (optionally filtered by status) for the admin dashboard.

FINES
add_fine(borrow_id, amount)
	Creates a fine for a borrow record (e.g. overdue return).

pay_fine(fine_id)
	Marks a fine as paid and updates the payment date.

get_user_fines(user_id)
	Retrieves all fines for a specific user.

get_all_fines(paid_status=None)
	Returns all fines (optionally filtered by status) for admin reporting.

VIEW LOGS
log_book_view(user_id, book_id)
	Records when a user views a book (used for recommendations/search tracking).

get_user_view_history(user_id)
	Returns the list of books a user has viewed.

get_most_viewed_books(limit=10)
	Returns the top-viewed books (used for dashboard analytics).

ADMIN ANALYTICS
get_library_stats()	
    Returns summarized library metrics: active users, total books, active borrows, and unpaid fines