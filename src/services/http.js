import axios from 'axios';

const http = axios.create({
  baseURL: 'http://localhost:5000',
  timeout: 30000,
  withCredentials: true, // Enable cookies for session-based auth
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'
  }
});

let requestQueue = [];
let isOnline = navigator.onLine;

const processQueue = () => {
  if (isOnline && requestQueue.length > 0) {
    const queuedRequests = [...requestQueue];
    requestQueue = [];
    queuedRequests.forEach(config => {
      http(config).catch(() => {});
    });
  }
};

window.addEventListener('online', () => {
  isOnline = true;
  processQueue();
});

window.addEventListener('offline', () => {
  isOnline = false;
});

const retryRequest = async (config, retryCount = 0) => {
  try {
    // Create a new axios instance for retry to avoid circular references
    const retryHttp = axios.create({
      baseURL: 'http://localhost:5000',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    });
    
    return await retryHttp(config);
  } catch (error) {
    if (retryCount < 3 && (!error.response || error.response.status >= 500)) {
      const delay = Math.pow(2, retryCount) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
      return retryRequest(config, retryCount + 1);
    }
    throw error;
  }
};

http.interceptors.request.use(
  (config) => {
    if (process.env.NODE_ENV === 'development') {
      console.log('Request:', config);
    }

    // For session-based auth, we don't need to add Authorization header
    // Cookies are automatically sent with withCredentials: true

    if (!isOnline) {
      requestQueue.push(config);
      return Promise.reject(new Error('Offline - Request queued'));
    }

    return config;
  },
  (error) => Promise.reject(error)
);

http.interceptors.response.use(
  (response) => {
    if (process.env.NODE_ENV === 'development') {
      console.log('Response:', response);
    }

    if (response.data && typeof response.data === 'object' && 'data' in response.data) {
      response.data = response.data.data;
    }

    return response;
  },
  async (error) => {
    if (process.env.NODE_ENV === 'development') {
      console.log('Response Error:', error);
    }

    if (error.response && error.response.status === 401) {
      // Clear session data and redirect to login
      localStorage.removeItem('user');
      localStorage.removeItem('csrf_token');
      window.location.href = '/login';
      return Promise.reject(error);
    }

    if (!error.response && error.request) {
      try {
        return await retryRequest(error.config);
      } catch (retryError) {
        if (process.env.NODE_ENV === 'development') {
          console.error('Network error after retries:', retryError.message);
        }
        return Promise.reject(new Error('Network error. Please check your connection.'));
      }
    }

    return Promise.reject(error);
  }
);

export default http;