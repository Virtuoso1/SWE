import React, { useState, useEffect } from 'react';
import { useLocation, Link } from 'react-router-dom';
import '../styles/layouts.css';

const UserLayout = ({ children, className = '' }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const location = useLocation();

  const navigationItems = [
    { path: '/dashboard', label: 'Dashboard' },
    { path: '/books', label: 'Books' },
    { path: '/students', label: 'Students' },
    { path: '/loans', label: 'Loans' }
  ];

  const isActive = (path) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileDropdownOpen && !event.target.closest('.profile-dropdown-container')) {
        setProfileDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [profileDropdownOpen]);

  // Handle escape key for dropdown
  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape' && profileDropdownOpen) {
        setProfileDropdownOpen(false);
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [profileDropdownOpen]);

  const handleLogout = () => {
    // Add logout logic here
    console.log('Logout clicked');
    setProfileDropdownOpen(false);
  };

  return (
    <div className="user-layout">
      <header className="user-header">
        <div className="user-header-brand">
          <Link to="/dashboard" className="user-header-logo">
            Library System
          </Link>
          
          <nav className="user-header-nav" role="navigation" aria-label="Main navigation">
            {navigationItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`user-header-nav-item ${isActive(item.path) ? 'active' : ''}`}
                aria-current={isActive(item.path) ? 'page' : undefined}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>

        <div>
          <button
            className="mobile-menu-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle mobile menu"
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-menu"
          >
            ☰
          </button>

          <div className="profile-dropdown-container">
            <button
              className="profile-dropdown-trigger"
              onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
              aria-label="User menu"
              aria-expanded={profileDropdownOpen}
              aria-haspopup="true"
            >
              <div className="profile-avatar" aria-hidden="true">
                U
              </div>
              <div className="profile-info">
                <span className="profile-name">User</span>
                <span className="profile-role">Student</span>
              </div>
              <span className="profile-dropdown-arrow" aria-hidden="true">▼</span>
            </button>

            <div className={`profile-dropdown-menu ${profileDropdownOpen ? 'show' : ''}`} role="menu">
              <Link to="/profile" className="profile-dropdown-item" role="menuitem" onClick={() => setProfileDropdownOpen(false)}>
                Profile
              </Link>
              <Link to="/settings" className="profile-dropdown-item" role="menuitem" onClick={() => setProfileDropdownOpen(false)}>
                Settings
              </Link>
              <hr className="profile-dropdown-divider" />
              <button
                className="profile-dropdown-item danger"
                role="menuitem"
                onClick={handleLogout}
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      <div
        id="mobile-menu"
        className={`mobile-menu ${mobileMenuOpen ? 'show' : ''}`}
        role="navigation"
        aria-label="Mobile navigation"
      >
        {navigationItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`mobile-menu-item ${isActive(item.path) ? 'active' : ''}`}
            aria-current={isActive(item.path) ? 'page' : undefined}
            onClick={() => setMobileMenuOpen(false)}
          >
            {item.label}
          </Link>
        ))}
      </div>

      <main className="user-main">
        <div className={`user-content-wrapper ${className}`}>
          {children}
        </div>
      </main>
    </div>
  );
};

export default UserLayout;