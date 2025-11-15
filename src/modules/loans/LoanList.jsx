import React, { useState, useEffect } from 'react';
import { getLoans } from './loan.api';
import styles from './LoanList.module.css';

const LoanList = () => {
  const [loans, setLoans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchLoans = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getLoans();
      setLoans(response.data?.borrows || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch loans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLoans();
  }, []);

  if (loading) {
    return (
      <div className={styles.loanListContainer}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingSpinner}></div>
          <p className={styles.loadingText}>Loading loans...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.loanListContainer}>
        <div className={styles.errorContainer}>
          <div className={styles.errorIcon}>⚠️</div>
          <h2 className={styles.errorTitle}>Error Loading Loans</h2>
          <p className={styles.errorMessage}>{error}</p>
          <button
            onClick={fetchLoans}
            className={styles.retryButton}
            aria-label="Retry loading loans"
          >
            🔄 Try Again
          </button>
        </div>
      </div>
    );
  }

  if (loans.length === 0) {
    return (
      <div className={styles.loanListContainer}>
        <div className={styles.emptyContainer}>
          <div className={styles.emptyIcon}>📖</div>
          <h2 className={styles.emptyTitle}>No Loans Found</h2>
          <p className={styles.emptyDescription}>There are currently no loans in the system.</p>
          <button
            onClick={fetchLoans}
            className={styles.emptyButton}
            aria-label="Refresh loans list"
          >
            🔄 Refresh
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.loanListContainer}>
      <div className={styles.loanListHeader}>
        <h1 className={styles.loanListTitle}>📚 Library Loans</h1>
        <button
          onClick={fetchLoans}
          className={styles.refreshButton}
          disabled={loading}
          aria-label="Refresh loans list"
        >
          <span className={styles.refreshIcon}>🔄</span>
          Refresh
        </button>
      </div>
      
      <div className={styles.loanListSection}>
        <div className={styles.tableResponsive}>
          <table className={styles.loansTable}>
            <thead>
              <tr>
                <th scope="col">Book Title</th>
                <th scope="col">Student Name</th>
                <th scope="col">Issue Date</th>
                <th scope="col">Return Date</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {loans.map((loan) => (
                <tr key={loan.borrow_id}>
                  <td>{loan.book_title || 'Unknown Book'}</td>
                  <td>{loan.user_name || 'Unknown User'}</td>
                  <td>{loan.borrow_date ? new Date(loan.borrow_date).toLocaleDateString() : 'Unknown'}</td>
                  <td>{loan.return_date ? new Date(loan.return_date).toLocaleDateString() : 'Not returned'}</td>
                  <td>
                    <span className={`${styles.statusBadge} ${
                      loan.status === 'borrowed' ? styles.statusActive :
                      loan.status === 'returned' ? styles.statusReturned :
                      styles.statusOverdue
                    }`}>
                      {loan.status === 'borrowed' ? '📖 Active' :
                       loan.status === 'returned' ? '✓ Returned' :
                       '⏰ Overdue'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LoanList;