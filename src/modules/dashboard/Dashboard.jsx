import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getDashboardStats, getRecentActivity, getPopularBooks, refreshDashboardData } from './dashboard.api';
import { getBooks } from '../books/book.api';
import { getMyProfile } from '../auth/auth.api';
import { getLoans, getAllLoans } from '../loans/loan.api';
import { getStudents } from '../students/student.api';
import styles from './Dashboard.module.css';

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [stats, setStats] = useState({
    totalBooks: 0,
    totalStudents: 0,
    activeLoans: 0,
    overdueLoans: 0,
    issuedBooks: 0
  });
  const [recentActivity, setRecentActivity] = useState([]);
  const [popularBooks, setPopularBooks] = useState([]);
  const [booksData, setBooksData] = useState([]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Try to use dashboard statistics endpoint first
      try {
        const dashboardStats = await getDashboardStats();
        
        if (dashboardStats && dashboardStats.statistics) {
          const stats = dashboardStats.statistics;
          
          // Set stats from dashboard API
          setStats({
            totalBooks: stats.total_books || 0,
            totalStudents: stats.active_users || 0,
            activeLoans: stats.active_borrows || 0,
            overdueLoans: stats.overdue_borrows || 0
          });
          
          // Still need to fetch other data for other sections
          const [booksResponse, studentsResponse] = await Promise.all([
            getBooks(),
            getStudents().catch(() => ({ data: { users: [] } }))
          ]);
          
          // Store books data for use in New Books section
          const booksDataArray = booksResponse?.data || [];
          setBooksData(booksDataArray);
          
          // Create activity from recent loans
          const loansData = stats.borrows?.total_borrows || [];
          const recentLoans = loansData.slice(0, 5).map((loan, index) => ({
            id: loan.id || index + 1,
            type: loan.status === 'returned' ? 'return' : 'loan',
            user: loan.user_name || 'Unknown User',
            book: loan.book_title || 'Unknown Book',
            time: loan.created_at ? new Date(loan.created_at).toLocaleString() : 'Unknown time'
          }));
          
          setRecentActivity(recentLoans);
          
          // Create popular books by combining loan data with actual book data
          const bookLoanCounts = {};
          loansData.forEach(loan => {
            if (loan.book_title) {
              bookLoanCounts[loan.book_title] = (bookLoanCounts[loan.book_title] || 0) + 1;
            }
          });
          
          // Create a map of book titles to book details for quick lookup
          const bookDetailsMap = {};
          booksDataArray.forEach(book => {
            bookDetailsMap[book.title] = book;
          });
          
          // Combine loan counts with book details
          const popularBooksData = Object.entries(bookLoanCounts)
            .sort(([,a], [,b]) => b - a) // Sort by loan count descending
            .slice(0, 4)
            .map(([title, count], index) => {
              const bookDetails = bookDetailsMap[title] || {};
              return {
                id: bookDetails.book_id || index + 1,
                title,
                author: bookDetails.author || 'Unknown Author',
                loans: count,
                category: bookDetails.category || 'Unknown',
                available: bookDetails.quantity_available || 0
              };
            });
          
          // If no loan data, show recent books as popular
          if (popularBooksData.length === 0 && booksDataArray.length > 0) {
            const recentBooks = booksDataArray
              .slice(0, 4)
              .map((book, index) => ({
                id: book.book_id,
                title: book.title,
                author: book.author,
                loans: 0,
                category: book.category,
                available: book.quantity_available
              }));
            setPopularBooks(recentBooks);
          } else {
            setPopularBooks(popularBooksData);
          }
          
          return; // Success, exit early
        }
      } catch (dashboardError) {
        console.log('Dashboard statistics endpoint not available, falling back to individual endpoints');
        
        // Fallback to individual endpoints
        const [booksResponse, profileResponse, allLoansResponse, studentsResponse] = await Promise.all([
          getBooks(),
          getMyProfile(),
          getAllLoans().catch(() => ({ data: { borrows: [] } })), // Get all loans, not just user's loans
          getStudents().catch(() => ({ data: { users: [] } })) // Handle permission errors
        ]);
        
        // Books API returns array directly, not nested in data.books
        const booksDataArray = booksResponse?.data || [];
        const booksCount = booksDataArray.length || 0;
        
        // Store books data for use in New Books section
        setBooksData(booksDataArray);
        
        // Get actual student count from users API
        const studentsData = studentsResponse?.data?.users || [];
        const studentsCount = studentsData.length > 0 ? studentsData.length : 1; // Fallback to 1 if no data
        
        const loansData = allLoansResponse?.data?.borrows || [];
        const activeLoans = loansData.filter(loan => loan.status === 'borrowed').length;
        const overdueLoans = loansData.filter(loan => {
          // Check if loan is overdue (status is borrowed and due date is in the past)
          if (loan.status !== 'borrowed') return false;
          const dueDate = new Date(loan.due_date);
          return dueDate < new Date();
        }).length;
        
        setStats({
          totalBooks: booksCount,
          totalStudents: studentsCount,
          activeLoans,
          overdueLoans
        });
        
        // Create activity from recent loans
        const recentLoans = loansData.slice(0, 5).map((loan, index) => ({
          id: loan.id || index + 1,
          type: loan.status === 'returned' ? 'return' : 'loan',
          user: loan.user_name || 'Unknown User',
          book: loan.book_title || 'Unknown Book',
          time: loan.created_at ? new Date(loan.created_at).toLocaleString() : 'Unknown time'
        }));
        
        setRecentActivity(recentLoans);
        
        // Create popular books by combining loan data with actual book data
        const bookLoanCounts = {};
        loansData.forEach(loan => {
          if (loan.book_title) {
            bookLoanCounts[loan.book_title] = (bookLoanCounts[loan.book_title] || 0) + 1;
          }
        });
        
        // Create a map of book titles to book details for quick lookup
        const bookDetailsMap = {};
        booksDataArray.forEach(book => {
          bookDetailsMap[book.title] = book;
        });
        
        // Combine loan counts with book details
        const popularBooksData = Object.entries(bookLoanCounts)
          .sort(([,a], [,b]) => b - a) // Sort by loan count descending
          .slice(0, 4)
          .map(([title, count], index) => {
            const bookDetails = bookDetailsMap[title] || {};
            return {
              id: bookDetails.book_id || index + 1,
              title,
              author: bookDetails.author || 'Unknown Author',
              loans: count,
              category: bookDetails.category || 'Unknown',
              available: bookDetails.quantity_available || 0
            };
          });
        
        // If no loan data, show recent books as popular
        if (popularBooksData.length === 0 && booksDataArray.length > 0) {
          const recentBooks = booksDataArray
            .slice(0, 4)
            .map((book, index) => ({
              id: book.book_id,
              title: book.title,
              author: book.author,
              loans: 0,
              category: book.category,
              available: book.quantity_available
            }));
          setPopularBooks(recentBooks);
        } else {
          setPopularBooks(popularBooksData);
        }
      }
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError(error.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      await fetchDashboardData();
    } catch (error) {
      console.error('Error refreshing dashboard:', error);
    } finally {
      setRefreshing(false);
    }
  };


  useEffect(() => {
    fetchDashboardData();
  }, []);

  const getActivityIcon = (type) => {
    return type === 'loan' ? '📚' : '📖';
  };

  const getActivityColor = (type) => {
    return type === 'loan' ? styles.activityLoan : styles.activityReturn;
  };

  if (loading) {
    return (
      <div className={styles.dashboard}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingSpinner}></div>
          <p className={styles.loadingText}>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.dashboard}>
        <div className={styles.errorContainer}>
          <div className={styles.errorIcon}>⚠️</div>
          <h3 className={styles.errorTitle}>Error Loading Dashboard</h3>
          <p className={styles.errorMessage}>{error}</p>
          <button
            className={styles.retryButton}
            onClick={handleRefresh}
            disabled={refreshing}
          >
            {refreshing ? 'Retrying...' : 'Retry'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.dashboard}>
      <div className={styles.dashboardHeader}>
        <div className={styles.headerContent}>
          <div>
            <h1 className={styles.dashboardTitle}>Dashboard</h1>
            <p className={styles.dashboardSubtitle}>Welcome to your library management system</p>
          </div>
          <button
            className={styles.refreshButton}
            onClick={handleRefresh}
            disabled={refreshing}
            aria-label="Refresh dashboard data"
          >
            <span className={`${styles.refreshIcon} ${refreshing ? styles.spinning : ''}`}>🔄</span>
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className={styles.statsGrid}>
        <Link to="/books" className={styles.statCard} style={{ textDecoration: 'none', color: 'inherit' }}>
          <div className={styles.statIcon}>📚</div>
          <div className={styles.statContent}>
            <h3 className={styles.statNumber}>{stats.totalBooks.toLocaleString()}</h3>
            <p className={styles.statLabel}>Total Books</p>
          </div>
          <div className={styles.statTrend}>+12%</div>
        </Link>

        <Link to="/students" className={styles.statCard} style={{ textDecoration: 'none', color: 'inherit' }}>
          <div className={styles.statIcon}>👥</div>
          <div className={styles.statContent}>
            <h3 className={styles.statNumber}>{stats.totalStudents.toLocaleString()}</h3>
            <p className={styles.statLabel}>Total Students</p>
          </div>
          <div className={styles.statTrend}>+8%</div>
        </Link>

        <Link to="/loans" className={styles.statCard} style={{ textDecoration: 'none', color: 'inherit' }}>
          <div className={styles.statIcon}>📖</div>
          <div className={styles.statContent}>
            <h3 className={styles.statNumber}>{stats.activeLoans}</h3>
            <p className={styles.statLabel}>Active Loans</p>
          </div>
          <div className={styles.statTrend}>+5%</div>
        </Link>

        <Link to="/loans" className={styles.statCard} style={{ textDecoration: 'none', color: 'inherit' }}>
          <div className={styles.statIcon}>⚠️</div>
          <div className={styles.statContent}>
            <h3 className={styles.statNumber}>{stats.overdueLoans}</h3>
            <p className={styles.statLabel}>Overdue Loans</p>
          </div>
          <div className={styles.statTrendNegative}>-3%</div>
        </Link>
      </div>

      <div className={styles.contentGrid}>
        <div className={styles.recentActivitySection}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>Recent Activity</h2>
            <Link to="/loans" className={styles.viewAllLink}>View All</Link>
          </div>
          <div className={styles.activityList}>
            {recentActivity.map((activity) => (
              <div key={activity.id} className={styles.activityItem}>
                <div className={`${styles.activityIcon} ${getActivityColor(activity.type)}`}>
                  {getActivityIcon(activity.type)}
                </div>
                <div className={styles.activityContent}>
                  <p className={styles.activityText}>
                    <span className={styles.activityUser}>{activity.user}</span>
                    {activity.type === 'loan' ? ' borrowed ' : ' returned '}
                    <span className={styles.activityBook}>{activity.book}</span>
                  </p>
                  <p className={styles.activityTime}>{activity.time}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className={styles.popularBooksSection}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>Popular Books</h2>
            <Link to="/books" className={styles.viewAllLink}>View All</Link>
          </div>
          <div className={styles.booksList}>
            {popularBooks.map((book) => (
              <div key={book.id} className={styles.bookItem}>
                <div className={styles.bookCover}>
                  <div className={styles.bookCoverPlaceholder}>📚</div>
                </div>
                <div className={styles.bookInfo}>
                  <h4 className={styles.bookTitle}>{book.title}</h4>
                  <p className={styles.bookAuthor}>{book.author}</p>
                  <div className={styles.bookStats}>
                    <span className={styles.loanCount}>{book.loans} loans</span>
                    {book.category && <span className={styles.bookCategory}>{book.category}</span>}
                    {book.available !== undefined && (
                      <span className={`${styles.availability} ${book.available > 0 ? styles.available : styles.unavailable}`}>
                        {book.available > 0 ? `${book.available} available` : 'Out of stock'}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>


        <div className={styles.newBooksSection}>
          <div className={styles.sectionHeader}>
            <h2 className={styles.sectionTitle}>New Books</h2>
            <Link to="/books" className={styles.viewAllLink}>View All</Link>
          </div>
          <div className={styles.booksList}>
            {booksData.slice(0, 4).map((book) => (
              <div key={book.book_id} className={styles.bookItem}>
                <div className={styles.bookCover}>
                  <div className={styles.bookCoverPlaceholder}>📚</div>
                </div>
                <div className={styles.bookInfo}>
                  <h4 className={styles.bookTitle}>{book.title}</h4>
                  <p className={styles.bookAuthor}>{book.author}</p>
                  <div className={styles.bookStats}>
                    {book.category && <span className={styles.bookCategory}>{book.category}</span>}
                    {book.year_published && <span className={styles.bookYear}>{book.year_published}</span>}
                    <span className={`${styles.availability} ${book.quantity_available > 0 ? styles.available : styles.unavailable}`}>
                      {book.quantity_available > 0 ? `${book.quantity_available} available` : 'Out of stock'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className={styles.quickActions}>
        <h2 className={styles.sectionTitle}>Quick Actions</h2>
        <div className={styles.actionsGrid}>
          <Link to="/books/add" className={styles.actionCard}>
            <div className={styles.actionIcon}>➕</div>
            <h3 className={styles.actionTitle}>Add Book</h3>
            <p className={styles.actionDescription}>Add a new book to the library</p>
          </Link>
          
          <Link to="/students/add" className={styles.actionCard}>
            <div className={styles.actionIcon}>👤</div>
            <h3 className={styles.actionTitle}>Add Student</h3>
            <p className={styles.actionDescription}>Register a new student</p>
          </Link>
          
          <Link to="/loans/issue" className={styles.actionCard}>
            <div className={styles.actionIcon}>📖</div>
            <h3 className={styles.actionTitle}>Issue Loan</h3>
            <p className={styles.actionDescription}>Issue a book to a student</p>
          </Link>
          
          <Link to="/loans/return" className={styles.actionCard}>
            <div className={styles.actionIcon}>📚</div>
            <h3 className={styles.actionTitle}>Return Book</h3>
            <p className={styles.actionDescription}>Process a book return</p>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;