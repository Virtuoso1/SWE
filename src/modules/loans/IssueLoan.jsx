import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { issueLoan } from './loan.api';
import { getBooks } from '../books/book.api';
import { useAuth } from '../auth/AuthProvider';
import styles from './IssueLoan.module.css';

const IssueLoan = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [formData, setFormData] = useState({
    bookId: '',
    issueDate: new Date().toISOString().split('T')[0],
    dueDate: ''
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [books, setBooks] = useState([]);
  const [optionsLoading, setOptionsLoading] = useState(true);

  useEffect(() => {
    const fetchBooks = async () => {
      try {
        setOptionsLoading(true);
        const booksResponse = await getBooks();
        setBooks(booksResponse.data || []);
      } catch (error) {
        console.error('Error fetching books:', error);
        // Set empty array to prevent map errors
        setBooks([]);
        // Show user-friendly error message
        setErrors({
          submit: 'Failed to load books. Please refresh the page and try again.'
        });
      } finally {
        setOptionsLoading(false);
      }
    };

    fetchBooks();
  }, []);

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.bookId) {
      newErrors.bookId = 'Book is required';
    }
    
    if (!formData.issueDate) {
      newErrors.issueDate = 'Issue date is required';
    }
    
    if (!formData.dueDate) {
      newErrors.dueDate = 'Due date is required';
    }
    
    // Validate that due date is after issue date
    if (formData.issueDate && formData.dueDate) {
      const issueDate = new Date(formData.issueDate);
      const dueDate = new Date(formData.dueDate);
      if (dueDate <= issueDate) {
        newErrors.dueDate = 'Due date must be after issue date';
      }
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      // Calculate due days from the selected dates
      const issueDate = new Date(formData.issueDate);
      const dueDate = new Date(formData.dueDate);
      const dueDays = Math.ceil((dueDate - issueDate) / (1000 * 60 * 60 * 24));
      
      await issueLoan({
        book_id: parseInt(formData.bookId, 10),
        due_days: dueDays
      });
      navigate('/loans');
    } catch (error) {
      setErrors({ submit: error.message || 'Failed to issue loan' });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (optionsLoading) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.loadingSpinner}></div>
        <p className={styles.loadingText}>Loading options...</p>
      </div>
    );
  }

  return (
    <div className={styles.issueLoanContainer}>
      <div className={styles.issueLoanCard}>
        <div className={styles.issueLoanHeader}>
          <div className={styles.issueLoanIcon}>📚</div>
          <h1 className={styles.issueLoanTitle}>Issue New Loan</h1>
          <p className={styles.issueLoanSubtitle}>Lend a book to a student</p>
        </div>
        
        {errors.submit && (
          <div className={styles.errorAlert} role="alert">
            <div className={styles.errorAlertTitle}>
              <span>⚠️</span>
              Loan Issue Failed
            </div>
            <div className={styles.errorAlertMessage}>{errors.submit}</div>
          </div>
        )}
        
        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.formField}>
            <label htmlFor="bookId" className={styles.formLabel}>Book</label>
            <select
              id="bookId"
              name="bookId"
              value={formData.bookId}
              onChange={handleChange}
              className={`${styles.formSelect} ${errors.bookId ? styles.formInputError : ''}`}
              disabled={isSubmitting}
              aria-describedby={errors.bookId ? 'bookId-error' : undefined}
            >
              <option value="">Select a book</option>
              {books.map((book) => (
                <option key={book.book_id || `book-${Math.random()}`} value={book.book_id}>
                  {book.title || 'Unknown Book'}
                </option>
              ))}
            </select>
            {errors.bookId && (
              <span id="bookId-error" className={styles.formErrorText} role="alert">
                {errors.bookId}
              </span>
            )}
          </div>
          
          <div className={styles.formField}>
            <label className={styles.formLabel}>Borrower</label>
            <div className={styles.formReadonly}>
              {user?.full_name || 'Current User'} (ID: {user?.user_id || 'Unknown'})
            </div>
          </div>
          
          <div className={styles.formField}>
            <label htmlFor="issueDate" className={styles.formLabel}>Issue Date</label>
            <input
              type="date"
              id="issueDate"
              name="issueDate"
              value={formData.issueDate}
              onChange={handleChange}
              className={`${styles.formInput} ${errors.issueDate ? styles.formInputError : ''}`}
              disabled={isSubmitting}
              aria-describedby={errors.issueDate ? 'issueDate-error' : undefined}
            />
            {errors.issueDate && (
              <span id="issueDate-error" className={styles.formErrorText} role="alert">
                {errors.issueDate}
              </span>
            )}
          </div>
          
          <div className={styles.formField}>
            <label htmlFor="dueDate" className={styles.formLabel}>Due Date</label>
            <input
              type="date"
              id="dueDate"
              name="dueDate"
              value={formData.dueDate}
              onChange={handleChange}
              className={`${styles.formInput} ${errors.dueDate ? styles.formInputError : ''}`}
              disabled={isSubmitting}
              aria-describedby={errors.dueDate ? 'dueDate-error' : undefined}
            />
            {errors.dueDate && (
              <span id="dueDate-error" className={styles.formErrorText} role="alert">
                {errors.dueDate}
              </span>
            )}
          </div>
          
          <div className={styles.formActions}>
            <button
              type="submit"
              className={styles.primaryButton}
              disabled={isSubmitting}
              aria-describedby={isSubmitting ? 'submitting' : undefined}
            >
              {isSubmitting ? '🔄 Issuing Loan...' : '📚 Issue Loan'}
            </button>
            <button
              type="button"
              className={styles.secondaryButton}
              onClick={() => navigate('/loans')}
              disabled={isSubmitting}
            >
              ❌ Cancel
            </button>
          </div>
          
          {isSubmitting && (
            <div id="submitting" className={styles.srOnly}>
              Issuing loan. Please wait.
            </div>
          )}
        </form>
      </div>
    </div>
  );
};

export default IssueLoan;