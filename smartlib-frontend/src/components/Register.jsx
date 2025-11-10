import React, { useState } from "react";
import { register } from "./library/api";


export default function Register({ onRegister }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleChange = e => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async e => {
    e.preventDefault();
    setError("");
    setSuccess("");
    try {
      const res = await register(form);
      if (res.success) {
        setSuccess("Registration successful!");
        onRegister && onRegister(res);
      } else {
        setError(res.message || "Registration failed");
      }
    } catch {
      setError("Server error");
    }
  };

  return (
    <div>
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <input name="username" placeholder="Username" value={form.username} onChange={handleChange} />
        <input name="password" type="password" placeholder="Password" value={form.password} onChange={handleChange} />
        <button type="submit">Register</button>
      </form>
      {error && <div style={{color:'red'}}>{error}</div>}
      {success && <div style={{color:'green'}}>{success}</div>}
    </div>
  );
}
