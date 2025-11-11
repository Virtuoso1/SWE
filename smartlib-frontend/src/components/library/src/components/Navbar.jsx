import React from "react";

const Navbar = () => {
  return (
    <nav className="bg-white shadow-md p-4 flex justify-between items-center">
      <h1 className="text-xl font-semibold">SmartLib Admin</h1>
      <button className="bg-blue-500 text-white px-4 py-2 rounded-md">Logout</button>
    </nav>
  );
};

export default Navbar;
