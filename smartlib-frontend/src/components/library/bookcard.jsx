import React from "react";

export default function BookCard({ book, onDelete }) {
  const handleBorrow = () => {
    alert(`You borrowed "${book.title}"`);
  };

  return (
    <div className="card shadow-sm">
      <div className="card-body">
        <h5 className="card-title">{book.title}</h5>
        <p className="card-text">👤 {book.author}</p>
        <p className="card-text">
          🏷️ Category: {book.category}
        </p>
        <p className={`fw-bold ${book.available ? "text-success" : "text-danger"}`}>
          {book.available ? "Available" : "Not Available"}
        </p>
        <div className="d-flex justify-content-between">
          <button
            className="btn btn-sm btn-primary"
            onClick={handleBorrow}
            disabled={!book.available}
          >
            Borrow
          </button>
          <button
            className="btn btn-sm btn-danger"
            onClick={() => onDelete(book.id)}
            
            
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}
