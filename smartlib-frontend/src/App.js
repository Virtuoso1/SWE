import './App.css';
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import BookDetails from "./components/Library/BookDetails";
import BorrowResponse from "./components/Library/BorrowResponse";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/library" element={<BookList />} />
        <Route path="/book/:id" element={<BookDetails />} />
        <Route path="/borrow/:id" element={<BorrowResponse />} />
      </Routes>
    </Router>
  );
}

export default App;
