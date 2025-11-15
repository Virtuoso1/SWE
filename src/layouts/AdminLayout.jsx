import React, { useState, useEffect } from 'react';
import { useLocation, Link } from 'react-router-dom';
import '../styles/layouts.css';

const AdminLayout = ({ children, className = '' }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();

  const navigationItems = [
    { path: '/dashboard', label: 'Dashboard', icon: '📊' },
    { path: '/books', label: 'Books', icon: '📚' },
    { path: '/students', label: 'Students', icon: '👥' },
    { path: '/loans', label: 'Loans', icon: '📋' },
    { path: '/reports', label: 'Reports', icon: '📈' },
    { path: '/settings', label: 'Settings', icon: '⚙️' }
  ];

  const isActive = (path) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const getBreadcrumbs = () => {
    const pathSegments = location.pathname.split('/').filter(segment => segment);
    const breadcrumbs = [{ label: 'Home', path: '/' }];
    
    let currentPath = '';
    pathSegments.forEach(segment => {
      currentPath += `/${segment}`;
      const label = segment.charAt(0).toUpperCase() + segment.slice(1);
      breadcrumbs.push({ label, path: currentPath });
    });
    
    return breadcrumbs;
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
    <div className="admin-layout">
      <aside className={`admin-sidebar ${sidebarCollapsed ? 'collapsed' : ''} ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div className="admin-sidebar-header">
          {!sidebarCollapsed && <h3 className="admin-sidebar-title">Admin Panel</h3>}
          <button
            className="sidebar-toggle-btn"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!sidebarCollapsed}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
        
        <nav className="admin-sidebar-nav" role="navigation" aria-label="Main navigation">
          {navigationItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`sidebar-nav-item ${isActive(item.path) ? 'active' : ''}`}
              aria-current={isActive(item.path) ? 'page' : undefined}
            >
              <span className="sidebar-nav-icon" aria-hidden="true">{item.icon}</span>
              {!sidebarCollapsed && <span className="sidebar-nav-text">{item.label}</span>}
            </Link>
          ))}
        </nav>
      </aside>

      <div className={`admin-main-content ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        <header className={`admin-header ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
          <nav className="breadcrumb-nav" aria-label="Breadcrumb navigation">
            {getBreadcrumbs().map((crumb, index) => (
              <div key={crumb.path} className="breadcrumb-item">
                {index > 0 && <span className="breadcrumb-separator" aria-hidden="true">›</span>}
                <Link
                  to={crumb.path}
                  className={`breadcrumb-link ${index === getBreadcrumbs().length - 1 ? 'active' : ''}`}
                  aria-current={index === getBreadcrumbs().length - 1 ? 'page' : undefined}
                >
                  {crumb.label}
                </Link>
              </div>
            ))}
          </nav>

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
                <span className="profile-role">Administrator</span>
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
        </header>

        <main className="admin-main">
          <div className={`admin-content-wrapper ${className}`}>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};

export default AdminLayout;