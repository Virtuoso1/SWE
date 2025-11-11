// src/components/library/editbookform.jsx
import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";

function EditBookForm() {
  const { id } = useParams(); // get the book id from the URL
  const navigate = useNavigate();

  // sample initial state — will load book details
  const [book, setBook] = useState({
    title: "",
    author: "",
    description: "",
  });

  useEffect(() => {
    // In a real app, you’d fetch the book details from the backend
    // For now, simulate fetching:
    const storedBook = {
      id,
      title: "Sample Book Title",
      author: "John Doe",
      description: "A placeholder book used for editing demo.",
    };
    setBook(storedBook);
  }, [id]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setBook((prevBook) => ({ ...prevBook, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    console.log("Edited book data:", book);
    // Later you’ll send this to your backend via a PUT/PATCH request
    navigate("/library"); // redirect to book list after editing
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
          <label>Description:</label>
          <textarea
            name="description"
            value={book.description}
            onChange={handleChange}
          />
        </div>
        <button type="submit">Save Changes</button>
      </form>
    </div>
  );
}

export default EditBookForm;
