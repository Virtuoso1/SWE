import http from '../../services/http.js';

export const getLoans = async () => {
  try {
    return await http.get('/borrows/my-borrows');
  } catch (error) {
    throw error;
  }
};

export const getLoan = async (id) => {
  try {
    return await http.get(`/borrows/${id}`);
  } catch (error) {
    throw error;
  }
};

export const issueLoan = async (data) => {
  try {
    return await http.post('/borrows/borrow', data);
  } catch (error) {
    throw error;
  }
};

export const returnBook = async (id, data = null) => {
  try {
    return await http.post(`/borrows/return/${id}`, data);
  } catch (error) {
    throw error;
  }
};

export const getAllLoans = async () => {
  try {
    return await http.get('/borrows/all');
  } catch (error) {
    throw error;
  }
};