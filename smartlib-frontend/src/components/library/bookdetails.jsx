import React from "react";
import { useParams, useNavigate } from "react-router-dom";
import booksData from "./librarydata";

export default function BookDetails() {
  const { id } = useParams();
  const navigate = useNavigate();

  const book = booksData.find((b) => b.id === parseInt(id));

  if (!book) {
    return (
      <div className="p-4">
        <h3>Book not found 📕</h3>
        <button className="btn btn-secondary mt-3" onClick={() => navigate(-1)}>
          Go Back
        </button>
      </div>
    );
  }

  const handleBorrow = () => {
    // Navigate to borrow request handler
    navigate(`/borrow/${book.id}`);
  };

  return (
    <div className="container mt-5">
      <div className="card shadow p-4">
        <h2>{book.title}</h2>
        <p><strong>Author:</strong> {book.author}</p>
        <p><strong>Category:</strong> {book.category}</p>
        <p><strong>Status:</strong> {book.available ? "Available ✅" : "Not Available ❌"}</p>

        <button
          className="btn btn-primary mt-3"
          onClick={handleBorrow}
          disabled={!book.available}
        >
          Borrow Book
        </button>

        <button className="btn btn-outline-secondary mt-3 ms-3" onClick={() => navigate(-1)}>
          Back to Library
        </button>
      </div>
    </div>
  );
}
