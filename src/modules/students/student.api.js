import http from '../../services/http.js';

export const getStudents = async () => {
  try {
    // Check if user is admin or librarian before making the request
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      const userData = JSON.parse(storedUser);
      const userRole = userData.role;
      
      // Only try to get all users if they have admin or librarian role
      if (userRole === 'admin' || userRole === 'librarian') {
        return await http.get('/users/all');
      }
    }
    
    // For non-admin users, directly go to fallback
    console.info('Non-admin user detected, fetching only user profile');
    const profileResponse = await http.get('/users/my-profile');
    // Transform single user response to match expected format
    return {
      data: {
        users: profileResponse.data?.user ? [profileResponse.data.user] : []
      }
    };
  } catch (error) {
    // Handle any unexpected errors
    console.error('Error fetching students:', error);
    // Return empty array instead of throwing to prevent complete failure
    return {
      data: {
        users: []
      }
    };
  }
};

export const getStudent = async (id) => {
  try {
    return await http.get(`/users/profile`);
  } catch (error) {
    throw error;
  }
};

export const createStudent = async (data) => {
  try {
    // Use the users endpoint for adding students, not auth/register
    // Transform the data to match what the backend expects
    const studentData = {
      full_name: data.full_name,
      email: data.email,
      password: data.password,
      student_id: data.student_id || '',
      class: data.class || '',
      role: 'student'
    };
    
    return await http.post('/users/create', studentData);
  } catch (error) {
    // Handle duplicate email errors more gracefully
    if (error.response?.status === 400 && error.response?.data?.message?.includes('already exists')) {
      throw new Error('A user with this email already exists. Please use a different email address.');
    }
    throw error;
  }
};

export const updateStudent = async (id, data) => {
  try {
    return await http.put(`/users/profile`, data);
  } catch (error) {
    throw error;
  }
};

export const deleteStudent = async (id) => {
  try {
    return await http.post(`/users/${id}/suspend`);
  } catch (error) {
    throw error;
  }
};