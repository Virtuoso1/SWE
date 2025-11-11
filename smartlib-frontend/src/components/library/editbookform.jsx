import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
<<<<<<< HEAD
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
=======

function EditBookForm() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [book, setBook] = useState({
    title: "",
    author: "",
    category: "",
  });

  useEffect(() => {
    fetch(`http://localhost:5000/books/${id}`)
      .then((res) => res.json())
      .then((data) => setBook(data))
      .catch((err) => console.error("Error fetching book:", err));
  }, [id]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setBook((prevBook) => ({ ...prevBook, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    fetch(`http://localhost:5000/books/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(book),
    })
      .then((res) => res.json())
      .then(() => navigate("/library"))
      .catch((err) => console.error("Error updating book:", err));
  };

  return (
    <div style={{ padding: "20px" }}>
      <h2>Edit Book</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Title:</label>
          <input
            type="text"
            name="title"
            value={book.title}
            onChange={handleChange}
            required
          />
        </div>
        <div>
          <label>Author:</label>
          <input
            type="text"
            name="author"
            value={book.author}
            onChange={handleChange}
            required
          />
        </div>
        <div>
          <label>Category:</label>
          <input
            type="text"
            name="category"
            value={book.category}
            onChange={handleChange}
            required
          />
        </div>
        <button type="submit" className="btn btn-primary">
          Save Changes
        </button>
      </form>
    </div>
  );
}

export default EditBookForm;
>>>>>>> 13b67996a850c28e649a1ae15bbba127a01c2d8e
