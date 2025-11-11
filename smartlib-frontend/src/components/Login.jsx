import React from "react";

export default function Login({ onLogin }) {
<<<<<<< HEAD
  const [form, setForm] = useState({ email: "", password: "" });
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

=======
  // ...existing code...
>>>>>>> 13b67996a850c28e649a1ae15bbba127a01c2d8e
  return (
    <div>
      <h2>Login</h2>
      <div style={{color:'blue', marginBottom:'1em'}}>If you see this message, the Login component is rendering.</div>
<<<<<<< HEAD
      <form onSubmit={handleSubmit}>
        <input name="email" placeholder="Email" value={form.email} onChange={handleChange} />
        <input name="password" type="password" placeholder="Password" value={form.password} onChange={handleChange} />
        <button type="submit">Login</button>
      </form>
      {error && <div style={{color:'red'}}>{error}</div>}
=======
      {/* ...existing login form code... */}
>>>>>>> 13b67996a850c28e649a1ae15bbba127a01c2d8e
    </div>
  );
}
