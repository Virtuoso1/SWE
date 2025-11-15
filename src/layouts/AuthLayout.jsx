import React from 'react';
import '../styles/layouts.css';

const AuthLayout = ({ children, className = '' }) => {
  return (
    <div className="auth-layout" role="main">
      <div className="auth-container">
        <div className={`auth-content-wrapper ${className}`}>
          {children}
        </div>
      </div>
    </div>
  );
};

export default AuthLayout;