import React from "react";
import { NavLink } from "react-router-dom";

const Sidebar = () => {
  return (
    <div className="w-64 bg-white shadow-lg p-4">
      <h2 className="text-2xl font-bold mb-6 text-center">Admin Panel</h2>
      <ul className="space-y-3">
        <li><NavLink to="/" className="block hover:text-blue-500">🏠 Dashboard</NavLink></li>
        <li><NavLink to="/users" className="block hover:text-blue-500">👥 Users</NavLink></li>
        <li><NavLink to="/books" className="block hover:text-blue-500">📚 Books</NavLink></li>
        <li><NavLink to="/borrow-requests" className="block hover:text-blue-500">📩 Borrow Requests</NavLink></li>
        <li><NavLink to="/current-borrowed" className="block hover:text-blue-500">📖 Current Borrowed</NavLink></li>
        <li><NavLink to="/overdue" className="block hover:text-blue-500">⏰ Overdue</NavLink></li>
        <li><NavLink to="/reports" className="block hover:text-blue-500">📊 Reports</NavLink></li>
        <li><NavLink to="/fines" className="block hover:text-blue-500">💰 Fines</NavLink></li>
        <li><NavLink to="/notifications" className="block hover:text-blue-500">🔔 Notifications</NavLink></li>
        <li><NavLink to="/settings" className="block hover:text-blue-500">⚙️ Settings</NavLink></li>
      </ul>
    </div>
  );
};

export default Sidebar;
