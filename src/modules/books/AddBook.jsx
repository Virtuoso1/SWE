import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createBook } from './book.api';
import styles from './AddBook.module.css';

const AddBook = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    title: '',
    author: '',
    isbn: '',
    genre: ''
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitMessage, setSubmitMessage] = useState('');

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.title.trim()) {
      newErrors.title = 'Title is required';
    }
    
    if (!formData.author.trim()) {
      newErrors.author = 'Author is required';
    }
    
    if (!formData.isbn.trim()) {
      newErrors.isbn = 'ISBN is required';
    } else if (formData.isbn.length < 10) {
      newErrors.isbn = 'ISBN must be at least 10 characters';
    }
    
    if (!formData.genre.trim()) {
      newErrors.genre = 'Genre is required';
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
    setSubmitMessage('');
    
    try {
      await createBook(formData);
      setSubmitMessage('Book added successfully!');
      setFormData({
        title: '',
        author: '',
        isbn: '',
        genre: ''
      });
      setErrors({});
      
      setTimeout(() => {
        navigate('/books');
      }, 1500);
    } catch (error) {
      setSubmitMessage(error.message || 'Failed to add book');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.icon}>📚</div>
        <h1 className={styles.title}>Add New Book</h1>
        <p className={styles.subtitle}>Enter the book details to add it to the library collection</p>
      </div>
      
      {submitMessage && (
        <div className={`${styles.message} ${submitMessage.includes('success') ? styles.success : styles.error}`}>
          {submitMessage}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className={styles.form}>
        <div className={styles.formGroup}>
          <label htmlFor="title" className={styles.label}>Title *</label>
          <input
            type="text"
            id="title"
            name="title"
            value={formData.title}
            onChange={handleChange}
            className={`${styles.input} ${errors.title ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.title ? 'title-error' : undefined}
          />
          {errors.title && (
            <span id="title-error" className={styles.errorMessage}>
              {errors.title}
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
            className={`${styles.input} ${errors.author ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.author ? 'author-error' : undefined}
          />
          {errors.author && (
            <span id="author-error" className={styles.errorMessage}>
              {errors.author}
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
            className={`${styles.input} ${errors.isbn ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.isbn ? 'isbn-error' : undefined}
          />
          {errors.isbn && (
            <span id="isbn-error" className={styles.errorMessage}>
              {errors.isbn}
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
            className={`${styles.input} ${errors.genre ? styles.error : ''}`}
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.genre ? 'genre-error' : undefined}
          />
          {errors.genre && (
            <span id="genre-error" className={styles.errorMessage}>
              {errors.genre}
            </span>
          )}
        </div>
        
        <div className={styles.formActions}>
          <button
            type="submit"
            className={styles.submitButton}
            disabled={isSubmitting}
            aria-describedby={submitMessage ? 'submit-message' : undefined}
          >
            {isSubmitting ? (
              <>
                <span className={styles.loading}></span>
                Adding Book...
              </>
            ) : (
              'Add Book'
            )}
          </button>
          <button
            type="button"
            className={styles.cancelButton}
            onClick={() => navigate('/books')}
            disabled={isSubmitting}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
};

export default AddBook;