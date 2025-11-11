import React, { useState } from "react";
//import { searchBooks } from "./library/api";

export default function Search() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSearch = async e => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const data = await searchBooks(query);
      setResults(data.books || []);
    } catch {
      setError("Search failed");
    }
    setLoading(false);
  };

  return (
    <div>
      <h2>Search Books</h2>
      <form onSubmit={handleSearch}>
        <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search..." />
        <button type="submit">Search</button>
      </form>
      {loading && <div>Loading...</div>}
      {error && <div style={{color:'red'}}>{error}</div>}
      <ul>
        {results.map(book => (
          <li key={book.id || book.title}>{book.title}</li>
        ))}
      </ul>
    </div>
  );
}
