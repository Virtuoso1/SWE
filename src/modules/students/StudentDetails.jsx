import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { getStudent } from './student.api';
import styles from './StudentDetails.module.css';

const StudentDetails = () => {
  const { id } = useParams();
  const [student, setStudent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStudentDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getStudent(id);
      setStudent(response.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch student details');
      console.error('Error fetching student details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchStudentDetails();
    }
  }, [id]);

  if (loading) {
    return (
      <div className={styles.studentDetailsContainer}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingSpinner}></div>
          <p className={styles.loadingText}>Loading student details...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.studentDetailsContainer}>
        <div className={styles.errorContainer}>
          <div className={styles.errorIcon}>⚠️</div>
          <h2 className={styles.errorTitle}>Error Loading Student Details</h2>
          <p className={styles.errorMessage}>{error}</p>
          <button onClick={fetchStudentDetails} className={styles.retryButton} aria-label="Retry loading student details">
            🔄 Try Again
          </button>
        </div>
      </div>
    );
  }

  if (!student) {
    return (
      <div className={styles.studentDetailsContainer}>
        <div className={styles.emptyContainer}>
          <div className={styles.emptyIcon}>👤</div>
          <h2 className={styles.emptyTitle}>Student Not Found</h2>
          <p className={styles.emptyDescription}>The student you're looking for doesn't exist or has been removed.</p>
          <button onClick={fetchStudentDetails} className={styles.emptyButton} aria-label="Refresh student details">
            🔄 Refresh
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.studentDetailsContainer}>
      <div className={styles.studentDetailsHeader}>
        <h1 className={styles.studentDetailsTitle}>Student Details</h1>
        <button 
          onClick={fetchStudentDetails} 
          className={styles.refreshButton}
          aria-label="Refresh student details"
        >
          <span className={styles.refreshIcon}>🔄</span>
          Refresh
        </button>
      </div>
      
      <div className={styles.studentDetailsGrid}>
        <div className={styles.infoCard}>
          <h2 className={styles.infoCardTitle}>👤 Student Information</h2>
          <div className={styles.infoGrid}>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Name</span>
              <span className={styles.infoValue}>
                {student.full_name || student.name || `${student.first_name || ''} ${student.last_name || ''}`.trim() || 'Unknown Student'}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Student ID</span>
              <span className={styles.infoValue}>{student.user_id || student.id || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Email</span>
              <span className={styles.infoValue}>{student.email || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Phone</span>
              <span className={styles.infoValue}>{student.phone || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Class</span>
              <span className={styles.infoValue}>{student.class || student.grade || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Enrollment Date</span>
              <span className={styles.infoValue}>
                {student.enrollment_date ? new Date(student.enrollment_date).toLocaleDateString() : 'N/A'}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Status</span>
              <span className={`${styles.statusBadge} ${
                student.status === 'active' || student.active ? styles.statusActive : styles.statusInactive
              }`}>
                {student.status === 'active' || student.active ? '✅ Active' : '❌ Inactive'}
              </span>
            </div>
          </div>
        </div>
        
        <>
          {student.address && (
            <div className={`${styles.infoCard} ${styles.addressCard}`}>
              <h2 className={styles.infoCardTitle}>📍 Address</h2>
              <div className={styles.infoValue}>{student.address}</div>
            </div>
          )}
          
          {student.notes && (
            <div className={`${styles.infoCard} ${styles.notesCard}`}>
              <h2 className={styles.infoCardTitle}>📝 Notes</h2>
              <div className={styles.infoValue}>{student.notes}</div>
            </div>
          )}
        </>
      </div>
      
      <div className={styles.actionButtons}>
        <button 
          className={styles.backButton} 
          onClick={() => window.history.back()}
          aria-label="Go back to students list"
        >
          ← Back to Students
        </button>
      </div>
    </div>
  );
};

export default StudentDetails;