import React, { useState, useEffect, useContext } from 'react';
import AuthContext from './AuthContext';
import { login as loginApi } from './auth.api';

const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const login = async (credentials) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await loginApi(credentials);
      const { success, user: userData, csrf_token } = response.data;
      
      if (success) {
        // Store user data and CSRF token for session-based auth
        localStorage.setItem('user', JSON.stringify(userData));
        localStorage.setItem('csrf_token', csrf_token);
        setUser(userData);
        setIsAuthenticated(true);
        setLoading(false);
        
        return { success: true };
      } else {
        throw new Error(response.data.message || 'Login failed');
      }
    } catch (err) {
      const errorMessage = err.response?.data?.message || 'Login failed';
      setError(errorMessage);
      setLoading(false);
      
      return { success: false, error: errorMessage };
    }
  };

  const logout = () => {
    localStorage.removeItem('user');
    localStorage.removeItem('csrf_token');
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
    setError(null);
  };

  const checkToken = () => {
    const storedUser = localStorage.getItem('user');
    
    if (storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        setUser(userData);
        setIsAuthenticated(true);
        setLoading(false);
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        setToken(null);
        setUser(null);
        setIsAuthenticated(false);
        setLoading(false);
      }
    } else {
      setToken(null);
      setUser(null);
      setIsAuthenticated(false);
      setLoading(false);
    }
  };

  useEffect(() => {
    checkToken();
  }, []);

  const value = {
    isAuthenticated,
    token,
    user,
    loading,
    error,
    login,
    logout,
    checkToken
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export { AuthProvider, useAuth };
export default AuthProvider;