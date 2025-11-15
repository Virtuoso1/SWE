import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { getBook } from './book.api';
import styles from './BookDetails.module.css';

const BookDetails = () => {
  const { id } = useParams();
  const [book, setBook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchBookDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getBook(id);
      setBook(response.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch book details');
      console.error('Error fetching book details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchBookDetails();
    }
  }, [id]);

  if (loading) {
    return (
      <div className={styles.bookDetailsContainer}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingSpinner}></div>
          <p className={styles.loadingText}>Loading book details...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.bookDetailsContainer}>
        <div className={styles.errorContainer}>
          <div className={styles.errorIcon}>⚠️</div>
          <h2 className={styles.errorTitle}>Error Loading Book Details</h2>
          <p className={styles.errorMessage}>{error}</p>
          <button onClick={fetchBookDetails} className={styles.retryButton} aria-label="Retry loading book details">
            🔄 Try Again
          </button>
        </div>
      </div>
    );
  }

  if (!book) {
    return (
      <div className={styles.bookDetailsContainer}>
        <div className={styles.emptyContainer}>
          <div className={styles.emptyIcon}>📖</div>
          <h2 className={styles.emptyTitle}>Book Not Found</h2>
          <p className={styles.emptyDescription}>The book you're looking for doesn't exist or has been removed.</p>
          <button onClick={fetchBookDetails} className={styles.emptyButton} aria-label="Refresh book details">
            🔄 Refresh
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.bookDetailsContainer}>
      <div className={styles.bookDetailsHeader}>
        <h1 className={styles.bookDetailsTitle}>Book Details</h1>
        <button 
          onClick={fetchBookDetails} 
          className={styles.refreshButton}
          aria-label="Refresh book details"
        >
          <span className={styles.refreshIcon}>🔄</span>
          Refresh
        </button>
      </div>
      
      <div className={styles.bookDetailsGrid}>
        <div className={styles.infoCard}>
          <h2 className={styles.infoCardTitle}>📖 Book Information</h2>
          <div className={styles.infoGrid}>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Title</span>
              <span className={styles.infoValue}>{book.title || 'Unknown Title'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Author</span>
              <span className={styles.infoValue}>{book.author || 'Unknown Author'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Publication Year</span>
              <span className={styles.infoValue}>{book.year_published || book.publication_year || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>ISBN</span>
              <span className={styles.infoValue}>{book.isbn || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Genre</span>
              <span className={styles.infoValue}>{book.category || book.genre || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Publisher</span>
              <span className={styles.infoValue}>{book.publisher || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Pages</span>
              <span className={styles.infoValue}>{book.page_count || book.pages || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Language</span>
              <span className={styles.infoValue}>{book.language || 'N/A'}</span>
            </div>
          </div>
        </div>
        
        <div className={styles.infoCard}>
          <h2 className={styles.infoCardTitle}>📊 Availability Status</h2>
          <div className={styles.infoGrid}>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Status</span>
              <span className={`${styles.statusBadge} ${
                (book.quantity_available > 0 || book.available) ? styles.statusAvailable : styles.statusBorrowed
              }`}>
                {(book.quantity_available > 0 || book.available) ? '✅ Available' : '📖 Borrowed'}
              </span>
            </div>
            {book.due_date && (
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Due Date</span>
                <span className={styles.infoValue}>{new Date(book.due_date).toLocaleDateString()}</span>
              </div>
            )}
          </div>
        </div>
        
        <>
          {book.description && (
            <div className={`${styles.infoCard} ${styles.descriptionCard}`}>
              <h2 className={styles.infoCardTitle}>📝 Description</h2>
              <div className={styles.infoValue}>{book.description}</div>
            </div>
          )}
          
          {book.location && (
            <div className={`${styles.infoCard} ${styles.locationCard}`}>
              <h2 className={styles.infoCardTitle}>📍 Location</h2>
              <div className={styles.infoValue}>{book.location}</div>
            </div>
          )}
        </>
      </div>
      
      <div className={styles.actionButtons}>
        <button 
          className={styles.backButton} 
          onClick={() => window.history.back()}
          aria-label="Go back to books list"
        >
          ← Back to Books
        </button>
      </div>
    </div>
  );
};

export default BookDetails;