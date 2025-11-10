import React, { useState } from "react";
import booksData from "../librarydata";
import BookCard from "./bookcard";

export default function BookList() {
  const [books, setBooks] = useState(booksData);
  const [searchTerm, setSearchTerm] = useState("");

  const filteredBooks = books.filter(
    (book) =>
      book.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      book.author.toLowerCase().includes(searchTerm.toLowerCase()) ||
      book.category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDelete = (id) => {
    setBooks(books.filter((book) => book.id !== id));
  };

  return (
    <div className="container mt-4">
      <h2>📚 Library Catalogue</h2>
      <input
        type="text"
        placeholder="Search by title, author, or category"
        className="form-control mb-3"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />

      <div className="row">
        {filteredBooks.map((book) => (
          <div className="col-md-4 mb-3" key={book.id}>
            <BookCard book={book} onDelete={handleDelete} />
          </div>
        ))}
      </div>
    </div>
  );
}

