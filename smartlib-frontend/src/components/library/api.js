// API module for Smart Library Frontend
const API_BASE_URL = 'http://localhost:5000';

// Helper function for making API requests
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    credentials: 'include',
    ...options,
  };

  try {
    const response = await fetch(url, config);
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.message || `HTTP error! status: ${response.status}`);
    }
    
    return data;
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}

// Authentication functions
export async function login(credentials) {
  try {
    const response = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function register(userData) {
  try {
    // Note: Backend doesn't have a register endpoint yet, but frontend expects it
    // This is a placeholder implementation
    const response = await apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function logout() {
  try {
    const response = await apiRequest('/auth/logout', {
      method: 'POST',
    });
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function checkAuth() {
  try {
    const response = await apiRequest('/auth/check');
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

// Books functions
export async function getBooks() {
  try {
    const response = await apiRequest('/books');
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function getBookById(bookId) {
  try {
    const response = await apiRequest(`/books/${bookId}`);
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function addBook(bookData) {
  try {
    const response = await apiRequest('/books', {
      method: 'POST',
      body: JSON.stringify(bookData),
    });
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function deleteBook(bookId) {
  try {
    const response = await apiRequest(`/books/${bookId}`, {
      method: 'DELETE',
    });
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}

export async function searchBooks(query) {
  try {
    // Using the filter endpoint for search functionality
    const response = await apiRequest('/books/filter', {
      method: 'GET',
    });
    
    // Filter results based on query (client-side filtering since backend doesn't have full-text search)
    if (response && Array.isArray(response)) {
      const filteredBooks = response.filter(book =>
        (book.title && book.title.toLowerCase().includes(query.toLowerCase())) ||
        (book.author && book.author.toLowerCase().includes(query.toLowerCase())) ||
        (book.category && book.category.toLowerCase().includes(query.toLowerCase()))
      );
      return { books: filteredBooks };
    }
    
    return { books: [] };
  } catch (error) {
    return { success: false, message: error.message, books: [] };
  }
}

// Dashboard function
export async function getDashboard() {
  try {
    // Since there's no dedicated dashboard endpoint, we'll get all books
    const response = await apiRequest('/books');
    return { books: response };
  } catch (error) {
    return { success: false, message: error.message, books: [] };
  }
}

// Filter books function
export async function filterBooks(filters) {
  try {
    const params = new URLSearchParams();
    
    if (filters.title) params.append('title', filters.title);
    if (filters.author) params.append('author', filters.author);
    if (filters.category) params.append('category', filters.category);
    if (filters.isbn) params.append('isbn', filters.isbn);
    if (filters.year) params.append('year', filters.year);
    
    const response = await apiRequest(`/books/filter?${params.toString()}`);
    return response;
  } catch (error) {
    return { success: false, message: error.message };
  }
}