import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getStudent, updateStudent } from './student.api';
import styles from './EditStudent.module.css';

const EditStudent = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    student_id: '',
    class: ''
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [validationErrors, setValidationErrors] = useState({});

  const validateField = (name, value) => {
    const errors = {};
    
    switch (name) {
      case 'name':
        if (!value.trim()) {
          errors.name = 'Name is required';
        } else if (value.length < 2) {
          errors.name = 'Name must be at least 2 characters';
        } else if (value.length > 100) {
          errors.name = 'Name must be less than 100 characters';
        }
        break;
        
      case 'email':
        if (!value.trim()) {
          errors.email = 'Email is required';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          errors.email = 'Please enter a valid email address';
        }
        break;
        
      case 'student_id':
        if (!value.trim()) {
          errors.student_id = 'Student ID is required';
        }
        break;
        
      case 'class':
        if (!value.trim()) {
          errors.class = 'Class is required';
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
      await updateStudent(id, formData);
      setSuccessMessage('Student updated successfully!');
      
      setTimeout(() => {
        navigate(`/students/${id}`);
      }, 2000);
    } catch (err) {
      let errorMessage = 'Failed to update student';
      
      if (err.response) {
        switch (err.response.status) {
          case 400:
            errorMessage = 'Invalid student data provided';
            break;
          case 404:
            errorMessage = 'Student not found';
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
    const fetchStudent = async () => {
      try {
        setLoading(true);
        setError('');
        const response = await getStudent(id);
        const studentData = response.data;
        
        setFormData({
          name: studentData.name || `${studentData.first_name} ${studentData.last_name}` || '',
          email: studentData.email || '',
          student_id: studentData.student_id || studentData.id || '',
          class: studentData.class || studentData.grade || ''
        });
      } catch (err) {
        let errorMessage = 'Failed to fetch student details';
        
        if (err.response) {
          switch (err.response.status) {
            case 404:
              errorMessage = 'Student not found';
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
      fetchStudent();
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

  if (error && !formData.name) {
    return (
      <div className={styles.errorContainer}>
        <h3>Error</h3>
        <p>{error}</p>
        <button onClick={() => navigate('/students')} className={styles.backButton}>
          Back to Students
        </button>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.icon}>✏️</div>
        <h1 className={styles.title}>Edit Student</h1>
        <p className={styles.subtitle}>Update student information in library system</p>
      </div>
      
      {successMessage && (
        <div className={`${styles.message} ${styles.success}`} role="alert">
          <div className={styles.messageTitle}>
            <span className={styles.messageIcon}>✅</span>
            Success
          </div>
          <div className={styles.messageContent}>{successMessage}</div>
        </div>
      )}
      
      {error && (
        <div className={`${styles.message} ${styles.error}`} role="alert">
          <div className={styles.messageTitle}>
            <span className={styles.messageIcon}>⚠️</span>
            Error
          </div>
          <div className={styles.messageContent}>{error}</div>
        </div>
      )}
      
      <form onSubmit={handleSubmit} className={styles.form} noValidate>
        <div className={styles.formGroup}>
          <label htmlFor="name" className={styles.label}>Name *</label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.name ? styles.error : ''}`}
            placeholder="Enter student's full name"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.name ? 'name-error' : undefined}
            maxLength="100"
          />
          {validationErrors.name && (
            <span id="name-error" className={styles.errorMessage} role="alert">
              {validationErrors.name}
            </span>
          )}
        </div>
       
        <div className={styles.formGroup}>
          <label htmlFor="email" className={styles.label}>Email *</label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.email ? styles.error : ''}`}
            placeholder="Enter student's email address"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.email ? 'email-error' : undefined}
          />
          {validationErrors.email && (
            <span id="email-error" className={styles.errorMessage} role="alert">
              {validationErrors.email}
            </span>
          )}
        </div>
       
        <div className={styles.formGroup}>
          <label htmlFor="student_id" className={styles.label}>Student ID *</label>
          <input
            type="text"
            id="student_id"
            name="student_id"
            value={formData.student_id}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.student_id ? styles.error : ''}`}
            placeholder="Enter student ID"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.student_id ? 'student_id-error' : undefined}
          />
          {validationErrors.student_id && (
            <span id="student_id-error" className={styles.errorMessage} role="alert">
              {validationErrors.student_id}
            </span>
          )}
        </div>
       
        <div className={styles.formGroup}>
          <label htmlFor="class" className={styles.label}>Class *</label>
          <input
            type="text"
            id="class"
            name="class"
            value={formData.class}
            onChange={handleChange}
            className={`${styles.input} ${validationErrors.class ? styles.error : ''}`}
            placeholder="Enter class or grade"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={validationErrors.class ? 'class-error' : undefined}
          />
          {validationErrors.class && (
            <span id="class-error" className={styles.errorMessage} role="alert">
              {validationErrors.class}
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
                Updating Student...
              </>
            ) : (
              'Update Student'
            )}
          </button>
          <button
            type="button"
            className={styles.cancelButton}
            onClick={() => navigate(`/students/${id}`)}
            disabled={isSubmitting}
          >
            Cancel
          </button>
        </div>
       
        {isSubmitting && (
          <div id="submitting" className={styles.srOnly}>
            Updating student information. Please wait.
          </div>
        )}
      </form>
    </div>
  );
};

export default EditStudent;