import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { Login, Register } from './modules/auth';
import { BookList, BookDetails, AddBook, EditBook } from './modules/books';
import { StudentList, StudentDetails, AddStudent, EditStudent } from './modules/students';
import { LoanList, IssueLoan, ReturnBook } from './modules/loans';
import { Dashboard } from './modules/dashboard';
import PrivateRoute from './components/PrivateRoute';

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      
      <Route path="/dashboard" element={<PrivateRoute children={<Dashboard />} />} />
      
      <Route path="/books" element={<PrivateRoute children={<BookList />} />} />
      <Route path="/books/:id" element={<PrivateRoute children={<BookDetails />} />} />
      <Route path="/books/add" element={<PrivateRoute children={<AddBook />} />} />
      <Route path="/books/edit/:id" element={<PrivateRoute children={<EditBook />} />} />
      
      <Route path="/students" element={<PrivateRoute children={<StudentList />} />} />
      <Route path="/students/:id" element={<PrivateRoute children={<StudentDetails />} />} />
      <Route path="/students/add" element={<PrivateRoute children={<AddStudent />} />} />
      <Route path="/students/edit/:id" element={<PrivateRoute children={<EditStudent />} />} />
      
      <Route path="/loans" element={<PrivateRoute children={<LoanList />} />} />
      <Route path="/loans/issue" element={<PrivateRoute children={<IssueLoan />} />} />
      <Route path="/loans/return" element={<PrivateRoute children={<ReturnBook />} />} />
      <Route path="/loans/return/:id" element={<PrivateRoute children={<ReturnBook />} />} />
    </Routes>
  );
};

export default App;