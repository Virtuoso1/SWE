import React, { useState, useEffect } from 'react';
import { getStudents } from './student.api';
import styles from './StudentList.module.css';

const StudentList = () => {
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStudents = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await getStudents();
      setStudents(response.data?.users || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch students');
      console.error('Error fetching students:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStudents();
  }, []);

  if (loading) {
    return (
      <div className={styles.studentListContainer}>
        <div className={styles.loadingContainer}>
          <div className={styles.loadingSpinner}></div>
          <p className={styles.loadingText}>Loading students...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={styles.studentListContainer}>
        <div className={styles.errorContainer}>
          <div className={styles.errorIcon}>⚠️</div>
          <h2 className={styles.errorTitle}>Error Loading Students</h2>
          <p className={styles.errorMessage}>{error}</p>
          <button onClick={fetchStudents} className={styles.retryButton} aria-label="Retry loading students">
            🔄 Try Again
          </button>
        </div>
      </div>
    );
  }

  if (students.length === 0) {
    return (
      <div className={styles.studentListContainer}>
        <div className={styles.emptyContainer}>
          <div className={styles.emptyIcon}>👥</div>
          <h2 className={styles.emptyTitle}>No Students Available</h2>
          <p className={styles.emptyDescription}>There are currently no students in the system.</p>
          <button onClick={fetchStudents} className={styles.emptyButton} aria-label="Refresh students list">
            🔄 Refresh
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.studentListContainer}>
      <div className={styles.studentListHeader}>
        <h1 className={styles.studentListTitle}>👥 Student Directory</h1>
        <button 
          onClick={fetchStudents} 
          className={styles.refreshButton}
          aria-label="Refresh students list"
        >
          <span className={styles.refreshIcon}>🔄</span>
          Refresh
        </button>
      </div>
      
      <div className={styles.studentListSection}>
        <div className={styles.tableResponsive}>
          <table className={styles.studentsTable}>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Name</th>
                <th scope="col">Email</th>
                <th scope="col">Phone</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {students.map((student, index) => (
                <tr key={student.user_id || student.id || `student-${index}`}>
                  <td>{student.user_id || student.id}</td>
                  <td>{student.full_name || student.name || `${student.first_name || ''} ${student.last_name || ''}`.trim() || 'Unknown Student'}</td>
                  <td>{student.email}</td>
                  <td>{student.phone || 'N/A'}</td>
                  <td>
                    <span className={`${styles.statusBadge} ${
                      student.status === 'active' ? styles.statusActive : styles.statusInactive
                    }`}>
                      {student.status === 'active' ? '✅ Active' : '❌ Inactive'}
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

export default StudentList;