import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import styles from './NavigationBar.module.css';

const NavigationBar = () => {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navigationItems = [
    { path: '/dashboard', label: 'Dashboard' },
    { path: '/books', label: 'Books' },
    { path: '/students', label: 'Students' },
    { path: '/loans', label: 'Loans' },
  ];

  const isActive = (path) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const toggleMobileMenu = () => {
    setMobileMenuOpen(!mobileMenuOpen);
  };

  return (
    <nav className={styles.navigationBar} role="navigation" aria-label="Main navigation">
      <div className={styles.navContainer}>
        <div className={styles.navBrand}>
          <Link to="/dashboard" className={styles.brandLink}>
            Library System
          </Link>
        </div>

        <div className={styles.navMenu}>
          <ul className={styles.navList}>
            {navigationItems.map((item) => (
              <li key={item.path} className={styles.navItem}>
                <Link
                  to={item.path}
                  className={`${styles.navLink} ${isActive(item.path) ? styles.navLinkActive : ''}`}
                  aria-current={isActive(item.path) ? 'page' : undefined}
                >
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        <button
          className={styles.mobileMenuToggle}
          onClick={toggleMobileMenu}
          aria-label="Toggle mobile menu"
          aria-expanded={mobileMenuOpen}
        >
          <span className={styles.hamburgerLine}></span>
          <span className={styles.hamburgerLine}></span>
          <span className={styles.hamburgerLine}></span>
        </button>
      </div>

      <div className={`${styles.mobileMenu} ${mobileMenuOpen ? styles.mobileMenuOpen : ''}`}>
        <ul className={styles.mobileNavList}>
          {navigationItems.map((item) => (
            <li key={item.path} className={styles.mobileNavItem}>
              <Link
                to={item.path}
                className={`${styles.mobileNavLink} ${isActive(item.path) ? styles.mobileNavLinkActive : ''}`}
                aria-current={isActive(item.path) ? 'page' : undefined}
                onClick={() => setMobileMenuOpen(false)}
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
};

export default NavigationBar;