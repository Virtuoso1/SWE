import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import booksData from "./librarydata";

export default function EditBookForm() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState("");
  const [category, setCategory] = useState("");
  const [available, setAvailable] = useState(true);

  useEffect(() => {
    const book = booksData.find((b) => b.id === parseInt(id));
    if (book) {
      setTitle(book.title);
      setAuthor(book.author);
      setCategory(book.category);
      setAvailable(book.available);
    }
  }, [id]);

  const handleSubmit = (e) => {
    e.preventDefault();
    // In a real app, this would update the book in the database
    // For now, we'll just navigate back to the library
    navigate("/library");
  };

  return (
    <div className="container mt-4">
      <div className="card p-4">
        <h4>Edit Book</h4>
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="title" className="form-label">Title</label>
            <input
              type="text"
              id="title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="form-control"
              required
            />
          </div>
          <div className="mb-3">
            <label htmlFor="author" className="form-label">Author</label>
            <input
              type="text"
              id="author"
              value={author}
              onChange={(e) => setAuthor(e.target.value)}
              className="form-control"
              required
            />
          </div>
          <div className="mb-3">
            <label htmlFor="category" className="form-label">Category</label>
            <input
              type="text"
              id="category"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="form-control"
              required
            />
          </div>
          <div className="mb-3 form-check">
            <input
              type="checkbox"
              id="available"
              checked={available}
              onChange={(e) => setAvailable(e.target.checked)}
              className="form-check-input"
            />
            <label htmlFor="available" className="form-check-label">Available</label>
          </div>
          <button type="submit" className="btn btn-primary me-2">
            Save Changes
          </button>
          <button 
            type="button" 
            className="btn btn-secondary" 
            onClick={() => navigate("/library")}
          >
            Cancel
          </button>
        </form>
      </div>
    </div>
  );
}