// App.js
import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import BookList from "./components/library/booklist";
import BookDetails from "./components/library/bookdetails";
import AddBookForm from "./components/library/addbookform";
import EditBookForm from "./components/library/editbookform";
import Login from "./components/Login";
import Register from "./components/Register";
import Dashboard from "./components/Dashboard";
import Search from "./components/Search";
import "./App.css";

function App() {
  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          <Route path="/" element={<Navigate to="/login" />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/search" element={<Search />} />
          <Route path="/library" element={<BookList />} />
          <Route path="/library/:id" element={<BookDetails />} />
          <Route path="/library/add" element={<AddBookForm />} />
          <Route path="/library/edit/:id" element={<EditBookForm />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
