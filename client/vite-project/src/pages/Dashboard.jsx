import React, { useEffect, useState } from "react";
import API from "../api/axios";

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
      <div className="w-full max-w-4xl bg-gray-800 shadow-lg rounded-lg p-6">
        {/* Header */}
        <h2 className="text-2xl font-bold flex items-center mb-4">
          <span className="mr-2">🔒</span> My Passwords
        </h2>

        {/* Add Password Form */}
        <form className="flex space-x-2 mb-6">
          <input
            type="text"
            placeholder="Website"
            className="flex-1 p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <input
            type="text"
            placeholder="Username"
            className="flex-1 p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <input
            type="password"
            placeholder="Password"
            className="flex-1 p-2 rounded bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-white font-semibold"
          >
            Add
          </button>
        </form>

        {/* Password Table */}
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="py-2 px-3">Website</th>
              <th className="py-2 px-3">Username</th>
              <th className="py-2 px-3">Password</th>
              <th className="py-2 px-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-gray-700">
              <td className="py-2 px-3">example.com</td>
              <td className="py-2 px-3">user123</td>
              <td className="py-2 px-3">••••••</td>
              <td className="py-2 px-3 space-x-2">
                <button className="px-3 py-1 bg-yellow-500 hover:bg-yellow-600 rounded text-black">
                  Edit
                </button>
                <button className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-white">
                  Delete
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}



