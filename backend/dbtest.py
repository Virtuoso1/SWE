from db.helpers import *

def main():
    print("Database initialized")

    add_user("Alice Sith", "lce@example.com", "password123", "student")
    add_book("1994", "George Owell", "Dstopian", "9788451524935", "Penguin", 1949, 3)

    print("\nUsers:")
    for user in get_all_users():
        print(user)

    print("\nBooks:")
    for book in list_books():
        print(book)

if __name__ == "__main__":
    main()
