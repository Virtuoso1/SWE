import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { createStudent } from './student.api';
import styles from './AddStudent.module.css';

const AddStudent = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    full_name: '',
    email: '',
    password: '',
    student_id: '',
    class: ''
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitMessage, setSubmitMessage] = useState('');

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.full_name.trim()) {
      newErrors.full_name = 'Name is required';
    }
    
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }
    
    if (!formData.password.trim()) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters long';
    }
    
    if (!formData.student_id.trim()) {
      newErrors.student_id = 'Student ID is required';
    }
    
    if (!formData.class.trim()) {
      newErrors.class = 'Class is required';
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
      // Send only the fields expected by the auth registration endpoint
      const registrationData = {
        full_name: formData.full_name,
        email: formData.email,
        password: formData.password,
        role: 'student' // Explicitly set role to student
      };
      
      await createStudent(registrationData);
      setSubmitMessage('Student added successfully!');
      setFormData({
        full_name: '',
        email: '',
        password: '',
        student_id: '',
        class: ''
      });
      setErrors({});
      
      setTimeout(() => {
        navigate('/students');
      }, 1500);
    } catch (error) {
      setSubmitMessage(error.message || 'Failed to add student');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.icon}>👨‍🎓</div>
        <h1 className={styles.title}>Add New Student</h1>
        <p className={styles.subtitle}>Register a new student in the library system</p>
      </div>
      
      {submitMessage && (
        <div className={`${styles.message} ${submitMessage.includes('success') ? styles.success : styles.error}`} role="alert">
          <div className={styles.messageTitle}>
            <span className={styles.messageIcon}>
              {submitMessage.includes('success') ? '✅' : '⚠️'}
            </span>
            {submitMessage.includes('success') ? 'Success' : 'Error'}
          </div>
          <div className={styles.messageContent}>{submitMessage}</div>
        </div>
      )}
      
      <form onSubmit={handleSubmit} className={styles.form}>
        <div className={styles.formGroup}>
          <label htmlFor="full_name" className={styles.label}>Full Name *</label>
          <input
            type="text"
            id="full_name"
            name="full_name"
            value={formData.full_name}
            onChange={handleChange}
            className={`${styles.input} ${errors.full_name ? styles.error : ''}`}
            placeholder="Enter student's full name"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.full_name ? 'full_name-error' : undefined}
          />
          {errors.full_name && (
            <span id="full_name-error" className={styles.errorMessage} role="alert">
              {errors.full_name}
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
            className={`${styles.input} ${errors.email ? styles.error : ''}`}
            placeholder="Enter student's email address"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.email ? 'email-error' : undefined}
          />
          {errors.email && (
            <span id="email-error" className={styles.errorMessage} role="alert">
              {errors.email}
            </span>
          )}
        </div>
       
        <div className={styles.formGroup}>
          <label htmlFor="password" className={styles.label}>Password *</label>
          <input
            type="password"
            id="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            className={`${styles.input} ${errors.password ? styles.error : ''}`}
            placeholder="Create a password (min 8 characters)"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.password ? 'password-error' : undefined}
          />
          {errors.password && (
            <span id="password-error" className={styles.errorMessage} role="alert">
              {errors.password}
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
            className={`${styles.input} ${errors.student_id ? styles.error : ''}`}
            placeholder="Enter student ID"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.student_id ? 'student_id-error' : undefined}
          />
          {errors.student_id && (
            <span id="student_id-error" className={styles.errorMessage} role="alert">
              {errors.student_id}
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
            className={`${styles.input} ${errors.class ? styles.error : ''}`}
            placeholder="Enter class or grade"
            disabled={isSubmitting}
            aria-required="true"
            aria-describedby={errors.class ? 'class-error' : undefined}
          />
          {errors.class && (
            <span id="class-error" className={styles.errorMessage} role="alert">
              {errors.class}
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
                Adding Student...
              </>
            ) : (
              'Add Student'
            )}
          </button>
          <button
            type="button"
            className={styles.cancelButton}
            onClick={() => navigate('/students')}
            disabled={isSubmitting}
          >
            Cancel
          </button>
        </div>
       
        {isSubmitting && (
          <div id="submitting" className={styles.srOnly}>
            Adding student. Please wait.
          </div>
        )}
      </form>
    </div>
  );
};

export default AddStudent;