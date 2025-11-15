import http from '../../services/http.js';

export const login = async (data) => {
  try {
    return await http.post('/auth/login', data);
  } catch (error) {
    throw error;
  }
};

export const register = async (data) => {
  try {
    return await http.post('/auth/register', data);
  } catch (error) {
    throw error;
  }
};

export const getMyProfile = async () => {
  try {
    return await http.get('/users/my-profile');
  } catch (error) {
    throw error;
  }
};