import React, { useEffect, useState } from "react";

// Dummy implementation for getDashboard
const getDashboard = async () => {
  // Replace with actual API call if available
  return { books: [
    { id: 1, title: "Sample Book 1" },
    { id: 2, title: "Sample Book 2" }
  ] };
};

export default function Dashboard() {
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getDashboard()
      .then(data => {
        setBooks(data.books || []);
        setLoading(false);
      })
      .catch(() => {
        setError("Failed to load books");
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div style={{color:'red'}}>{error}</div>;

  return (
    <div>
      <h2>Book Dashboard</h2>
      <ul>
        {books.map(book => (
          <li key={book.id || book.title}>{book.title}</li>
        ))}
      </ul>
    </div>
  );
}
