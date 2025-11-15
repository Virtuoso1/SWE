import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from './AuthProvider';
import { register as registerApi } from './auth.api';
import styles from './Auth.module.css';

const Register = () => {
  const [formData, setFormData] = useState({
    full_name: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'student'
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.full_name.trim()) {
      newErrors.full_name = 'Full name is required';
    }
    
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email is invalid';
    }
    
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    }
    
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    
    try {
      const response = await registerApi({
        full_name: formData.full_name,
        email: formData.email,
        password: formData.password,
        role: formData.role
      });
      
      // Auto-login after successful registration
      await login({
        email: formData.email,
        password: formData.password
      });
      
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Registration failed';
      setErrors({ submit: errorMessage });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.authContainer}>
      <div className={styles.authCard}>
        <div className={styles.authHeader}>
          <div className={styles.authIcon}>
            📚
          </div>
          <h1 className={styles.authTitle}>Create Account</h1>
          <p className={styles.authSubtitle}>Join our library community today</p>
        </div>
        
        <form onSubmit={handleSubmit} className={styles.authForm}>
          {errors.submit && (
            <div className={styles.authError} role="alert">
              <div className={styles.authErrorTitle}>
                <span className={styles.authErrorIcon}>⚠️</span>
                Registration Failed
              </div>
              <div className={styles.authErrorMessage}>{errors.submit}</div>
            </div>
          )}
          
          <div className={styles.authField}>
            <label htmlFor="full_name" className={styles.authLabel}>Full Name</label>
            <input
              type="text"
              id="full_name"
              name="full_name"
              value={formData.full_name}
              onChange={handleChange}
              className={styles.authInput}
              placeholder="Enter your full name"
              disabled={loading}
              aria-required="true"
              aria-describedby={errors.full_name ? 'full_name-error' : undefined}
            />
            {errors.full_name && (
              <span id="full_name-error" className={styles.authErrorText} role="alert">
                {errors.full_name}
              </span>
            )}
          </div>

          <div className={styles.authField}>
            <label htmlFor="email" className={styles.authLabel}>Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              className={styles.authInput}
              placeholder="Enter your email address"
              disabled={loading}
              aria-required="true"
              aria-describedby={errors.email ? 'email-error' : undefined}
            />
            {errors.email && (
              <span id="email-error" className={styles.authErrorText} role="alert">
                {errors.email}
              </span>
            )}
          </div>

          <div className={styles.authField}>
            <label htmlFor="password" className={styles.authLabel}>Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              className={styles.authInput}
              placeholder="Create a strong password (min 8 characters)"
              disabled={loading}
              aria-required="true"
              aria-describedby={errors.password ? 'password-error' : undefined}
            />
            {errors.password && (
              <span id="password-error" className={styles.authErrorText} role="alert">
                {errors.password}
              </span>
            )}
          </div>

          <div className={styles.authField}>
            <label htmlFor="confirmPassword" className={styles.authLabel}>Confirm Password</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              className={styles.authInput}
              placeholder="Re-enter your password"
              disabled={loading}
              aria-required="true"
              aria-describedby={errors.confirmPassword ? 'confirmPassword-error' : undefined}
            />
            {errors.confirmPassword && (
              <span id="confirmPassword-error" className={styles.authErrorText} role="alert">
                {errors.confirmPassword}
              </span>
            )}
          </div>

          <div className={styles.authField}>
            <label htmlFor="role" className={styles.authLabel}>Role</label>
            <select
              id="role"
              name="role"
              value={formData.role}
              onChange={handleChange}
              className={styles.authSelect}
              disabled={loading}
              aria-describedby={errors.role ? 'role-error' : undefined}
            >
              <option value="student">Student</option>
              <option value="admin">Admin</option>
            </select>
            {errors.role && (
              <span id="role-error" className={styles.authErrorText} role="alert">
                {errors.role}
              </span>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className={styles.authButton}
            aria-describedby={loading ? 'submitting' : undefined}
          >
            {loading ? (
              <div className={styles.authLoading}>
                <div className={styles.authSpinner}></div>
                Creating Account...
              </div>
            ) : (
              'Create Account'
            )}
          </button>
          
          {loading && (
            <div id="submitting" className={styles.srOnly}>
              Creating your account. Please wait.
            </div>
          )}
        </form>
        
        <div className={styles.authFooter}>
          <p className={styles.authFooterText}>
            Already have an account?{' '}
            <Link to="/login" className={styles.authLink}>
              Sign in here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;