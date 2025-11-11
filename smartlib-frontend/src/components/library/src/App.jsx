import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Users from "./pages/Users";
import Books from "./pages/Books";
import BorrowRequests from "./pages/BorrowRequests";
import CurrentBorrowed from "./pages/CurrentBorrowed";
import Overdue from "./pages/Overdue";
import Reports from "./pages/Reports";
import Fines from "./pages/Fines";
import Notifications from "./pages/Notifications";
import Settings from "./pages/Settings";

const App = () => {
  return (
    <Router>
      <div className="flex h-screen bg-gray-100">
        <Sidebar />
        <div className="flex flex-col flex-1">
          <Navbar />
          <div className="p-4 overflow-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/users" element={<Users />} />
              <Route path="/books" element={<Books />} />
              <Route path="/borrow-requests" element={<BorrowRequests />} />
              <Route path="/current-borrowed" element={<CurrentBorrowed />} />
              <Route path="/overdue" element={<Overdue />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/fines" element={<Fines />} />
              <Route path="/notifications" element={<Notifications />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
};

export default App;
