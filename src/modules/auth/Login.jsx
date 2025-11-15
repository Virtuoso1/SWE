import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { login } from './auth.api';
import { useAuth } from './AuthProvider';
import styles from './Auth.module.css';

const Login = () => {
  const navigate = useNavigate();
  const { login: authLogin } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const response = await login(formData);
      const result = await authLogin(formData);
      if (result.success) {
        navigate('/dashboard');
      } else {
        setError(result.error);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.authContainer}>
      <div className={styles.authCard}>
        <div className={styles.authHeader}>
          <div className={styles.authIcon}>
            🔐
          </div>
          <h1 className={styles.authTitle}>Welcome Back</h1>
          <p className={styles.authSubtitle}>Sign in to access your library dashboard</p>
        </div>
        
        <form onSubmit={handleSubmit} className={styles.authForm}>
          {error && (
            <div className={styles.authError} role="alert">
              <div className={styles.authErrorTitle}>
                <span className={styles.authErrorIcon}>⚠️</span>
                Login Failed
              </div>
              <div className={styles.authErrorMessage}>{error}</div>
            </div>
          )}
          
          <div className={styles.authField}>
            <label htmlFor="email" className={styles.authLabel}>Email/Username</label>
            <input
              type="text"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
              className={styles.authInput}
              placeholder="Enter your email or username"
              aria-describedby="email-error"
            />
          </div>
          
          <div className={styles.authField}>
            <label htmlFor="password" className={styles.authLabel}>Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              className={styles.authInput}
              placeholder="Enter your password"
              aria-describedby="password-error"
            />
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
                Logging in...
              </div>
            ) : (
              'Sign In'
            )}
          </button>
          
          {loading && (
            <div id="submitting" className="styles.srOnly">
              Logging in. Please wait.
            </div>
          )}
        </form>
        
        <div className={styles.authFooter}>
          <p className={styles.authFooterText}>
            Don't have an account?{' '}
            <Link to="/register" className={styles.authLink}>
              Create an account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;