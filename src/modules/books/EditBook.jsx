import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getBook, updateBook } from './book.api';
import styles from './EditBook.module.css';

const EditBook = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    title: '',
    author: '',
    isbn: '',
    genre: ''
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [validationErrors, setValidationErrors] = useState({});

  const validateField = (name, value) => {
    const errors = {};
    
    switch (name) {
      case 'title':
        if (!value.trim()) {
          errors.title = 'Title is required';
        } else if (value.length < 2) {
          errors.title = 'Title must be at least 2 characters';
        } else if (value.length > 100) {
          errors.title = 'Title must be less than 100 characters';
        }
        break;
        
      case 'author':
        if (!value.trim()) {
          errors.author = 'Author is required';
        } else if (value.length < 2) {
          errors.author = 'Author must be at least 2 characters';
        } else if (value.length > 100) {
          errors.author = 'Author must be less than 100 characters';
        }
        break;
        
      case 'isbn':
        if (!value.trim()) {
          errors.isbn = 'ISBN is required';
        } else if (!/^(?:ISBN(?:-1[03])?:? )?(?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]$/.test(value)) {
          errors.isbn = 'Please enter a valid ISBN format';
        }
        break;
        
      case 'genre':
        if (!value.trim()) {
          errors.genre = 'Genre is required';
        }
        break;
        
      default:
        break;
    }
    
    return errors;
  };

  const validateForm = () => {
    const errors = {};
    Object.keys(formData).forEach(field => {
      const fieldErrors = validateField(field, formData[field]);
      Object.assign(errors, fieldErrors);
    });
    
    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    const fieldErrors = validateField(name, value);
    setValidationErrors(prev => ({
      ...prev,
      ...fieldErrors
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setIsSubmitting(true);
    setError('');
    setSuccessMessage('');
    
    try {
      await updateBook(id, formData);
      setSuccessMessage('Book updated successfully!');
      
      setTimeout(() => {
        navigate(`/books/${id}`);
      }, 2000);
    } catch (err) {
      let errorMessage = 'Failed to update book';
      
      if (err.response) {
        switch (err.response.status) {
          case 400:
            errorMessage = 'Invalid book data provided';
            break;
          case 404:
            errorMessage = 'Book not found';
            break;
          case 500:
            errorMessage = 'Server error occurred';
            break;
          default:
            errorMessage = err.response.data?.message || 'An error occurred';
        }
      } else if (err.request) {
        errorMessage = 'Network error. Please check your connection.';
      }
      
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  useEffect(() => {
    const fetchBook = async () => {
      try {
        setLoading(true);
        setError('');
        const response = await getBook(id);
        const bookData = response.data;
        
        setFormData({
          title: bookData.title || '',
          author: bookData.author || '',
          isbn: bookData.isbn || '',
          genre: bookData.genre || ''
        });
      } catch (err) {
        let errorMessage = 'Failed to fetch book details';
        
        if (err.response) {
          switch (err.response.status) {
            case 404:
              errorMessage = 'Book not found';
              break;
            case 500:
              errorMessage = 'Server error occurred';
              break;
            default:
              errorMessage = err.response.data?.message || 'An error occurred';
          }
        } else if (err.request) {
          errorMessage = 'Network error. Please check your connection.';
        }
        
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchBook();
    }
  }, [id]);

  if (loading) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.skeletonForm}>
          <div className={styles.skeletonHeader}></div>
          <div className={styles.skeletonField}></div>
          <div className={styles.skeletonField}></div>
          <div className={styles.skeletonField}></div>
          <div className={styles.skeletonField}></div>
          <div className={styles.skeletonButtons}></div>
        </div>
      </div>
    );
  }

  if (error && !formData.title) {
    return (
      <div className={styles.errorContainer}>
        <h3>Error</h3>
        <p>{error}</p>
        <button onClick={() => navigate('/books')} className={styles.backButton}>
          Back to Books
        </button>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.icon}>✏️</div>
        <h1 className={styles.title}>Edit Book</h1>
        <p className={styles.subtitle}>Update the book information in the library collection</p>
      </div>
      
      {successMessage && (
        <div className={`${styles.message} ${styles.success}`} role="alert">
          {successMessage}
        </div>
      )}
      
      {error && (
        <div className={`${styles.message} ${styles.error}`} role="alert">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className={styles.form} noValidate>
        <div className={styles.formGroup}>
          <label htmlFor="title" className={styles.label}>Title *</label>
          <input
            type="text"
            id="title"
            name="title"
            value={formData.title}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.title ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.title ? 'title-error' : undefined}
            maxLength="100"
          />
          {validationErrors.title && (
            <span id="title-error" className={styles.errorMessage} role="alert">
              {validationErrors.title}
            </span>
          )}
        </div>
        
        <div className={styles.formGroup}>
          <label htmlFor="author" className={styles.label}>Author *</label>
          <input
            type="text"
            id="author"
            name="author"
            value={formData.author}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.author ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.author ? 'author-error' : undefined}
            maxLength="100"
          />
          {validationErrors.author && (
            <span id="author-error" className={styles.errorMessage} role="alert">
              {validationErrors.author}
            </span>
          )}
        </div>
        
        <div className={styles.formGroup}>
          <label htmlFor="isbn" className={styles.label}>ISBN *</label>
          <input
            type="text"
            id="isbn"
            name="isbn"
            value={formData.isbn}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.isbn ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.isbn ? 'isbn-error' : undefined}
            placeholder="e.g., 978-3-16-148410-0"
          />
          {validationErrors.isbn && (
            <span id="isbn-error" className={styles.errorMessage} role="alert">
              {validationErrors.isbn}
            </span>
          )}
        </div>
        
        <div className={styles.formGroup}>
          <label htmlFor="genre" className={styles.label}>Genre *</label>
          <input
            type="text"
            id="genre"
            name="genre"
            value={formData.genre}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.genre ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.genre ? 'genre-error' : undefined}
          />
          {validationErrors.genre && (
            <span id="genre-error" className={styles.errorMessage} role="alert">
              {validationErrors.genre}
            </span>
          )}
        </div>
        
        <div className={styles.formActions}>
          <button
            type="submit"
            className={styles.submitButton}
            disabled={isSubmitting}
            aria-describedby={isSubmitting ? 'submitting' : undefined}
          >
            {isSubmitting ? (
              <>
                <span className={styles.loading}></span>
                Updating Book...
              </>
            ) : (
              'Update Book'
            )}
          </button>
          <button
            type="button"
            className={styles.cancelButton}
            onClick={() => navigate(`/books/${id}`)}
            disabled={isSubmitting}
          >
            Cancel
          </button>
        </div>
        
        {isSubmitting && (
          <div id="submitting" className={styles.srOnly}>
            Updating book information. Please wait.
          </div>
        )}
      </form>
    </div>
  );
};

export default EditBook;