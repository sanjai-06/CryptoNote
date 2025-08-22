import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api/axios";
import PasswordGenerator from "../components/PasswordGenerator";

export default function Dashboard() {
  const [passwords, setPasswords] = useState([]);
  const [form, setForm] = useState({ website: "", username: "", password: "" });
  const [editingId, setEditingId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPasswords, setShowPasswords] = useState({});
  const navigate = useNavigate();

  // Fetch passwords on component mount
  useEffect(() => {
    fetchPasswords();
  }, []);

  const fetchPasswords = async () => {
    try {
      const res = await API.get("/passwords");
      setPasswords(res.data);
    } catch (err) {
      if (err.response?.status === 401) {
        localStorage.removeItem("token");
        navigate("/login");
      } else {
        setError("Failed to fetch passwords");
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      if (editingId) {
        // Update existing password
        const res = await API.put(`/passwords/${editingId}`, form);
        setPasswords(passwords.map(p => p._id === editingId ? res.data : p));
        setEditingId(null);
      } else {
        // Add new password
        const res = await API.post("/passwords", form);
        setPasswords([...passwords, res.data]);
      }
      setForm({ website: "", username: "", password: "" });
    } catch (err) {
      setError(err.response?.data?.message || "Operation failed");
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (password) => {
    setForm({
      website: password.website,
      username: password.username,
      password: password.password
    });
    setEditingId(password._id);
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Are you sure you want to delete this password?")) return;

    try {
      await API.delete(`/passwords/${id}`);
      setPasswords(passwords.filter(p => p._id !== id));
    } catch (err) {
      setError("Failed to delete password");
    }
  };

  const togglePasswordVisibility = (id) => {
    setShowPasswords(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-4">
      <div className="w-full max-w-6xl mx-auto bg-gray-800 shadow-lg rounded-lg p-6">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-3xl font-bold flex items-center">
            <span className="mr-2">🔒</span> My Passwords
          </h2>
          <button
            onClick={handleLogout}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded text-white font-semibold"
          >
            Logout
          </button>
        </div>

        {error && (
          <div className="bg-red-600 text-white p-3 rounded mb-4 text-center">
            {error}
          </div>
        )}

        {/* Add/Edit Password Form */}
        <form onSubmit={handleSubmit} className="flex flex-wrap gap-2 mb-6">
          <input
            type="text"
            placeholder="Website"
            value={form.website}
            onChange={(e) => setForm({ ...form, website: e.target.value })}
            className="flex-1 min-w-[200px] p-3 rounded bg-gray-700 border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
          <input
            type="text"
            placeholder="Username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            className="flex-1 min-w-[200px] p-3 rounded bg-gray-700 border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
          <div className="flex-1 min-w-[200px] relative">
            <input
              type="password"
              placeholder="Password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full p-3 rounded bg-gray-700 border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
            <div className="absolute right-2 top-1/2 transform -translate-y-1/2">
              <PasswordGenerator
                onPasswordGenerated={(password) => setForm({ ...form, password })}
              />
            </div>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 rounded text-white font-semibold"
          >
            {loading ? "..." : editingId ? "Update" : "Add"}
          </button>
          {editingId && (
            <button
              type="button"
              onClick={() => {
                setEditingId(null);
                setForm({ website: "", username: "", password: "" });
              }}
              className="px-6 py-3 bg-gray-600 hover:bg-gray-700 rounded text-white font-semibold"
            >
              Cancel
            </button>
          )}
        </form>

        {/* Password Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="py-3 px-4">Website</th>
                <th className="py-3 px-4">Username</th>
                <th className="py-3 px-4">Password</th>
                <th className="py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {passwords.length === 0 ? (
                <tr>
                  <td colSpan="4" className="py-8 px-4 text-center text-gray-400">
                    No passwords saved yet. Add your first password above!
                  </td>
                </tr>
              ) : (
                passwords.map((password) => (
                  <tr key={password._id} className="border-b border-gray-700 hover:bg-gray-750">
                    <td className="py-3 px-4">{password.website}</td>
                    <td className="py-3 px-4">{password.username}</td>
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono">
                          {showPasswords[password._id] ? password.password : "••••••••"}
                        </span>
                        <button
                          onClick={() => togglePasswordVisibility(password._id)}
                          className="text-blue-400 hover:text-blue-300"
                          title={showPasswords[password._id] ? "Hide" : "Show"}
                        >
                          {showPasswords[password._id] ? "👁️" : "👁️‍🗨️"}
                        </button>
                        <button
                          onClick={() => copyToClipboard(password.password)}
                          className="text-green-400 hover:text-green-300"
                          title="Copy to clipboard"
                        >
                          📋
                        </button>
                      </div>
                    </td>
                    <td className="py-3 px-4 space-x-2">
                      <button
                        onClick={() => handleEdit(password)}
                        className="px-3 py-1 bg-yellow-500 hover:bg-yellow-600 rounded text-black font-semibold"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(password._id)}
                        className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-white font-semibold"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}