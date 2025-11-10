// API utility for backend requests
const BASE_URL = "http://localhost:5000"; // Change port if needed

export async function login(data) {
  const res = await fetch(`${BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function register(data) {
  const res = await fetch(`${BASE_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function getDashboard() {
  const res = await fetch(`${BASE_URL}/dash`);
  return res.json();
}

export async function searchBooks(query) {
  const res = await fetch(`${BASE_URL}/search?query=${encodeURIComponent(query)}`);
  return res.json();
}