import React, { useState } from "react";

// Dummy implementation for login
const login = async (form) => {
  // Replace with actual API call if available
  if (form.username === "admin" && form.password === "admin") {
    return { success: true, message: "Login successful" };
  }
  return { success: false, message: "Invalid credentials" };
};

export default function Login({ onLogin }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");

  const handleChange = e => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async e => {
    e.preventDefault();
    setError("");
    try {
      const res = await login(form);
      if (res.success) {
        onLogin(res);
      } else {
        setError(res.message || "Login failed");
      }
    } catch {
      setError("Server error");
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <div style={{color:'blue', marginBottom:'1em'}}>If you see this message, the Login component is rendering.</div>
      <form onSubmit={handleSubmit}>
        <input name="username" placeholder="Username" value={form.username} onChange={handleChange} />
        <input name="password" type="password" placeholder="Password" value={form.password} onChange={handleChange} />
        <button type="submit">Login</button>
      </form>
      {error && <div style={{color:'red'}}>{error}</div>}
    </div>
  );
}
