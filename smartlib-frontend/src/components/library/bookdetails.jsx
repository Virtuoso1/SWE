import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

export default function BookDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [book, setBook] = useState(null);

  useEffect(() => {
    fetch(`http://localhost:5000/books/${id}`)
      .then((res) => res.json())
      .then((data) => setBook(data))
      .catch((err) => console.error("Error fetching book:", err));
  }, [id]);

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

  return (
    <div className="container mt-5">
      <div className="card shadow p-4">
        <h2>{book.title}</h2>
        <p><strong>Author:</strong> {book.author}</p>
        <p><strong>Category:</strong> {book.category}</p>
        <p><strong>Status:</strong> {book.available ? "Available ✅" : "Not Available ❌"}</p>
        <button
          className="btn btn-outline-secondary mt-3 ms-3"
          onClick={() => navigate(-1)}
        >
          Back to Library
        </button>
      </div>
    </div>
  );
}