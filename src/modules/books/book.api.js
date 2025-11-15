import http from '../../services/http.js';

export const getBooks = async () => {
  try {
    return await http.get('/books');
  } catch (error) {
    throw error;
  }
};

export const getBook = async (id) => {
  try {
    return await http.get(`/books/${id}`);
  } catch (error) {
    throw error;
  }
};

export const createBook = async (data) => {
  try {
    return await http.post('/books', data);
  } catch (error) {
    throw error;
  }
};

export const updateBook = async (id, data) => {
  try {
    return await http.put(`/books/${id}`, data);
  } catch (error) {
    throw error;
  }
};

export const deleteBook = async (id) => {
  try {
    return await http.delete(`/books/${id}`);
  } catch (error) {
    throw error;
  }
};