import React, { useState } from "react";

export default function AddBookForm({ onAdd }) {
  const [title, setTitle] = useState("");
  const [author, setAuthor] = useState("");
  const [category, setCategory] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const newBook = {
      id: Date.now(),
      title,
      author,
      category,
      available: true,
    };
    onAdd(newBook);
    setTitle("");
    setAuthor("");
    setCategory("");
  };

  return (
    <div className="card mt-4 p-3">
      <h4>Add New Book</h4>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="form-control mb-2"
          required
        />
        <input
          type="text"
          placeholder="Author"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          className="form-control mb-2"
          required
        />
        <input
          type="text"
          placeholder="Category"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="form-control mb-2"
          required
        />
        <button type="submit" className="btn btn-success">
          Add Book
        </button>
      </form>
    </div>
  );
}
