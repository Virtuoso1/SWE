import http from '../../services/http.js';

export const getDashboardStats = async () => {
  try {
    const response = await http.get('/dashboard/statistics');
    return response.data;
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    throw error;
  }
};

export const getRecentActivity = async () => {
  try {
    const response = await http.get('/dashboard/data');
    return response.data;
  } catch (error) {
    console.error('Error fetching recent activity:', error);
    throw error;
  }
};

export const getPopularBooks = async () => {
  try {
    const response = await http.get('/dashboard/data');
    return response.data;
  } catch (error) {
    console.error('Error fetching popular books:', error);
    throw error;
  }
};

export const refreshDashboardData = async () => {
  try {
    const [stats, activity, popularBooks] = await Promise.all([
      getDashboardStats(),
      getRecentActivity(),
      getPopularBooks()
    ]);
    
    return {
      stats,
      activity,
      popularBooks
    };
  } catch (error) {
    console.error('Error refreshing dashboard data:', error);
    throw error;
  }
};