import React, { useState, useEffect } from 'react';
import { getBooks } from './book.api';
import styles from './BookList.module.css';

const BookList = () => {
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchBooks = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getBooks();
      setBooks(response.data || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch books');
      console.error('Error fetching books:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBooks();
  }, []);

  if (loading) {
    return (
      <div className={styles.bookListContainer}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingSpinner}></div>
          <p className={styles.loadingText}>Loading books...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.bookListContainer}>
        <div className={styles.errorContainer}>
          <div className={styles.errorIcon}>⚠️</div>
          <h2 className={styles.errorTitle}>Error Loading Books</h2>
          <p className={styles.errorMessage}>{error}</p>
          <button onClick={fetchBooks} className={styles.retryButton} aria-label="Retry loading books">
            🔄 Try Again
          </button>
        </div>
      </div>
    );
  }

  if (books.length === 0) {
    return (
      <div className={styles.bookListContainer}>
        <div className={styles.emptyContainer}>
          <div className={styles.emptyIcon}>📚</div>
          <h2 className={styles.emptyTitle}>No Books Available</h2>
          <p className={styles.emptyDescription}>There are currently no books in the library.</p>
          <button onClick={fetchBooks} className={styles.emptyButton} aria-label="Refresh books list">
            🔄 Refresh
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.bookListContainer}>
      <div className={styles.bookListHeader}>
        <h1 className={styles.bookListTitle}>📚 Library Books</h1>
        <button 
          onClick={fetchBooks} 
          className={styles.refreshButton}
          aria-label="Refresh books list"
        >
          <span className={styles.refreshIcon}>🔄</span>
          Refresh
        </button>
      </div>
      
      <div className={styles.bookListSection}>
        <div className={styles.tableResponsive}>
          <table className={styles.booksTable}>
            <thead>
              <tr>
                <th scope="col">Title</th>
                <th scope="col">Author</th>
                <th scope="col">Publication Year</th>
                <th scope="col">ISBN</th>
                <th scope="col">Genre</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {books.map((book) => (
                <tr key={book.id || book.isbn || `book-${Math.random()}`}>
                  <td>{book.title || 'Unknown Title'}</td>
                  <td>{book.author || 'Unknown Author'}</td>
                  <td>{book.year_published || book.publication_year || 'N/A'}</td>
                  <td>{book.isbn || 'N/A'}</td>
                  <td>{book.category || book.genre || 'N/A'}</td>
                  <td>
                    <span className={`${styles.statusBadge} ${
                      (book.quantity_available > 0 || book.available) ? styles.statusAvailable : styles.statusBorrowed
                    }`}>
                      {(book.quantity_available > 0 || book.available) ? '✅ Available' : '📖 Borrowed'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default BookList;