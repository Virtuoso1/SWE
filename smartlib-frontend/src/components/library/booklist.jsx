import React, { useState, useEffect } from "react";
import BookCard from "./bookcard";
import "./BookList.css";

export default function BookList() {
  const [books, setBooks] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    fetch("http://localhost:5000/books")
      .then((response) => response.json())
      .then((data) => setBooks(data))
      .catch((error) => console.error("Error fetching books:", error));
  }, []);

  const handleDelete = (id) => {
    fetch(`http://localhost:5000/books/${id}`, { method: "DELETE" })
      .then((res) => res.json())
      .then(() => setBooks(books.filter((book) => book.id !== id)))
      .catch((err) => console.error("Error deleting book:", err));
  };

  const filteredBooks = books.filter((book) =>
    book.title.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="book-list-container">
      <h2 className="book-list-title">Book List</h2>
      <input
        type="text"
        className="book-search-input"
        placeholder="Search by title..."
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />
      <div className="book-list-grid">
        {filteredBooks.length === 0 ? (
          <p className="no-books-message">No books found.</p>
        ) : (
          filteredBooks.map((book) => (
            <BookCard key={book.id} book={book} onDelete={handleDelete} />
          ))
        )}
      </div>
    </div>
  );
}