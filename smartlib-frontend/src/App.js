// App.js
import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import BookList from "./components/library/booklist";
import BookDetails from "./components/library/bookdetails";
import AddBookForm from "./components/library/addbookform";
import EditBookForm from "./components/library/editbookform";
import "./App.css";

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/library" element={<BookList />} />
          <Route path="/library/:id" element={<BookDetails />} />
          <Route path="/library/add" element={<AddBookForm />} />
          <Route path="/library/edit/:id" element={<EditBookForm />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
