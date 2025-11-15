import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useParams } from 'react-router-dom';
import { getLoan, returnBook, getLoans } from './loan.api';
import styles from './ReturnBook.module.css';

const ReturnBook = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    loanId: id || ''
  });
  const [loading, setLoading] = useState(false);
  const [fetchLoading, setFetchLoading] = useState(true);
  const [error, setError] = useState(null);
  const [loan, setLoan] = useState(null);
  const [loans, setLoans] = useState([]);
  const [errors, setErrors] = useState({});

  useEffect(() => {
    const fetchData = async () => {
      try {
        setFetchLoading(true);
        setError(null);
        
        if (id) {
          // Fetch specific loan details
          const response = await getLoan(id);
          setLoan(response.data);
        } else {
          // Fetch all active loans for selection
          const response = await getLoans();
          const activeLoans = response.data?.borrows?.filter(loan => loan.status === 'borrowed') || [];
          setLoans(activeLoans);
        }
      } catch (err) {
        setError(err.message || 'Failed to fetch data');
      } finally {
        setFetchLoading(false);
      }
    };

    fetchData();
  }, [id]);

  const validateForm = () => {
    const newErrors = {};
    
    if (!id && !formData.loanId) {
      newErrors.loanId = 'Please select a loan to return';
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

  const [successMessage, setSuccessMessage] = useState(null);
  const [returnData, setReturnData] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    setReturnData(null);
    
    try {
      const loanIdToReturn = id || formData.loanId;
      const response = await returnBook(loanIdToReturn);
      
      if (response.data?.success) {
        setSuccessMessage(response.data?.message || 'Book returned successfully!');
        setReturnData(response.data);
        
        // Refresh the loans list if not returning a specific loan
        if (!id) {
          try {
            const loansResponse = await getLoans();
            const activeLoans = loansResponse.data?.borrows?.filter(loan => loan.status === 'borrowed') || [];
            setLoans(activeLoans);
          } catch (refreshErr) {
            console.error('Failed to refresh loans:', refreshErr);
          }
        }
        
        // Reset form
        setFormData({
          loanId: id || ''
        });
      } else {
        setError(response.data?.error || 'Failed to return book');
      }
    } catch (err) {
      setError(err.message || 'Failed to return book');
    } finally {
      setLoading(false);
    }
  };

  if (fetchLoading) {
    return (
      <div className={styles.loadingContainer}>
        <div className={styles.loadingSpinner}></div>
        <p className={styles.loadingText}>{id ? 'Loading loan details...' : 'Loading active loans...'}</p>
      </div>
    );
  }

  if (successMessage) {
    return (
      <div className={styles.returnBookContainer}>
        <div className={styles.returnBookCard}>
          <div className={styles.returnBookHeader}>
            <div className={styles.successIcon}>✅</div>
            <h1 className={styles.returnBookTitle}>Return Successful!</h1>
            <p className={styles.returnBookSubtitle}>{successMessage}</p>
          </div>
          
          {returnData && (
            <div className={styles.returnDetails}>
              <h3 className={styles.detailsTitle}>Return Details</h3>
              <div className={styles.detailsGrid}>
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>Book:</span>
                  <span className={styles.detailValue}>{returnData.book_title || 'Unknown Book'}</span>
                </div>
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>Borrower:</span>
                  <span className={styles.detailValue}>{returnData.user_name || 'Unknown User'}</span>
                </div>
                <div className={styles.detailItem}>
                  <span className={styles.detailLabel}>Return Date:</span>
                  <span className={styles.detailValue}>{returnData.return_date ? new Date(returnData.return_date).toLocaleDateString() : 'Unknown'}</span>
                </div>
                {returnData.days_overdue > 0 && (
                  <div className={styles.detailItem}>
                    <span className={styles.detailLabel}>Days Overdue:</span>
                    <span className={styles.detailValue}>{returnData.days_overdue}</span>
                  </div>
                )}
                {returnData.penalty_amount > 0 && (
                  <div className={styles.detailItem}>
                    <span className={styles.detailLabel}>Penalty Amount:</span>
                    <span className={styles.detailValue}>${returnData.penalty_amount.toFixed(2)}</span>
                  </div>
                )}
              </div>
              
              {returnData.penalty_amount > 0 && (
                <div className={styles.penaltyNotice}>
                  <p className={styles.penaltyText}>
                    ⚠️ A penalty of ${returnData.penalty_amount.toFixed(2)} has been applied for late return.
                  </p>
                </div>
              )}
            </div>
          )}
          
          <div className={styles.formActions}>
            <button
              onClick={() => {
                setSuccessMessage(null);
                setReturnData(null);
                setFormData({
                  loanId: id || ''
                });
              }}
              className={styles.primaryButton}
            >
              📚 Return Another Book
            </button>
            <button
              onClick={() => navigate('/loans')}
              className={styles.secondaryButton}
            >
              📋 View All Loans
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (error && !loan && !id) {
    return (
      <div className={styles.errorContainer}>
        <div className={styles.errorIcon}>⚠️</div>
        <h2 className={styles.errorTitle}>Error</h2>
        <p className={styles.errorMessage}>{error}</p>
        <button onClick={() => navigate('/loans')} className={styles.secondaryButton}>
          📚 Back to Loans
        </button>
      </div>
    );
  }

  return (
    <div className={styles.returnBookContainer}>
      <div className={styles.returnBookCard}>
        <div className={styles.returnBookHeader}>
          <div className={styles.returnBookIcon}>📖</div>
          <h1 className={styles.returnBookTitle}>{id ? 'Return Book' : 'Select Loan to Return'}</h1>
          <p className={styles.returnBookSubtitle}>
            {id ? 'Process book return and update loan status' : 'Choose an active loan to return'}
          </p>
          {loan && (
            <div className={styles.loanInfo}>
              <p><strong>Book:</strong> {loan.book?.title || 'Unknown Book'}</p>
              <p><strong>Student:</strong> {loan.student?.name || `${loan.student?.first_name || ''} ${loan.student?.last_name || ''}`.trim() || 'Unknown Student'}</p>
              <p><strong>Issue Date:</strong> {loan.issue_date || 'Unknown'}</p>
            </div>
          )}
        </div>
        
        {error && (
          <div className={styles.errorAlert} role="alert">
            <div className={styles.errorAlertMessage}>
              {error}
            </div>
          </div>
        )}
        
        <form onSubmit={handleSubmit} className={styles.form}>
          {!id && (
            <div className={styles.formGroup}>
              <label htmlFor="loanId" className={styles.formLabel}>Select Loan</label>
              <select
                id="loanId"
                name="loanId"
                value={formData.loanId}
                onChange={handleChange}
                className={`${styles.formSelect} ${errors.loanId ? styles.formInputError : ''}`}
                disabled={loading}
                aria-describedby={errors.loanId ? 'loanId-error' : undefined}
              >
                <option value="">Select a loan to return</option>
                {loans.map((loan) => (
                  <option key={loan.borrow_id || loan.id || `loan-${Math.random()}`} value={loan.borrow_id || loan.id}>
                    {loan.book_title || 'Unknown Book'} - {loan.user_name || 'Unknown User'} (Issued: {loan.borrow_date || loan.created_at ? new Date(loan.borrow_date || loan.created_at).toLocaleDateString() : 'Unknown'})
                  </option>
                ))}
              </select>
              {errors.loanId && (
                <span id="loanId-error" className={styles.formErrorText} role="alert">
                  {errors.loanId}
                </span>
              )}
            </div>
          )}
          
          
          <div className={styles.formActions}>
            <button
              type="submit"
              className={styles.primaryButton}
              disabled={loading}
              aria-describedby={loading ? 'submitting' : undefined}
            >
              {loading ? '🔄 Processing...' : '✅ Return Book'}
            </button>
            <button
              type="button"
              className={styles.secondaryButton}
              onClick={() => navigate('/loans')}
              disabled={loading}
            >
              ❌ Cancel
            </button>
          </div>
          
          {loading && (
            <div id="submitting" className={styles.srOnly}>
              Processing return. Please wait.
            </div>
          )}
        </form>
      </div>
    </div>
  );
};

export default ReturnBook;