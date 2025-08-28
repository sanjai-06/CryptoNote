import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api/axios";
import PasswordGenerator from "../components/PasswordGenerator";
import ChangePasswordModal from "../components/ChangePasswordModal";

export default function Dashboard() {
  const [passwords, setPasswords] = useState([]);
  const [form, setForm] = useState({ website: "", username: "", password: "" });
  const [editingId, setEditingId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPasswords, setShowPasswords] = useState({});
  const [showChangePasswordModal, setShowChangePasswordModal] = useState(false);
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white">
      {/* Animated background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
      </div>

      <div className="relative z-10 p-6">
        <div className="w-full max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
            <div className="flex items-center mb-4 md:mb-0">
              <div className="w-12 h-12 bg-gradient-to-r from-purple-500 to-blue-500 rounded-xl flex items-center justify-center mr-4">
                <span className="text-2xl">🔐</span>
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">
                  Password Vault
                </h1>
                <p className="text-gray-400">Manage your digital keys securely</p>
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={() => setShowChangePasswordModal(true)}
                className="px-6 py-3 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-xl text-purple-300 font-semibold transition-all duration-300 transform hover:scale-105"
              >
                <span className="mr-2">🔐</span> Change Master Password
              </button>
              <button
                onClick={handleLogout}
                className="px-6 py-3 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-xl text-red-300 font-semibold transition-all duration-300 transform hover:scale-105"
              >
                <span className="mr-2">🚪</span> Logout
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-4 rounded-xl mb-6 text-center backdrop-blur-sm">
              <span className="text-red-300">⚠️</span> {error}
            </div>
          )}

          {/* Add/Edit Password Form */}
          <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6 mb-8">
            <h3 className="text-xl font-semibold mb-4 flex items-center">
              <span className="mr-2">{editingId ? "✏️" : "➕"}</span>
              {editingId ? "Edit Password" : "Add New Password"}
            </h3>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Website (e.g., google.com)"
                    value={form.website}
                    onChange={(e) => setForm({ ...form, website: e.target.value })}
                    className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300"
                    required
                  />
                  <div className="absolute inset-y-0 right-0 flex items-center pr-4">
                    <span className="text-gray-400">🌐</span>
                  </div>
                </div>

                <div className="relative">
                  <input
                    type="text"
                    placeholder="Username or Email"
                    value={form.username}
                    onChange={(e) => setForm({ ...form, username: e.target.value })}
                    className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300"
                    required
                  />
                  <div className="absolute inset-y-0 right-0 flex items-center pr-4">
                    <span className="text-gray-400">👤</span>
                  </div>
                </div>

                <div className="relative">
                  <input
                    type="password"
                    placeholder="Password"
                    value={form.password}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                    className="w-full p-4 pr-16 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300"
                    required
                  />
                  <div className="absolute inset-y-0 right-0 flex items-center pr-2">
                    <PasswordGenerator
                      onPasswordGenerated={(password) => setForm({ ...form, password })}
                    />
                  </div>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row gap-3 pt-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 rounded-xl text-white font-semibold transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100"
                >
                  {loading ? (
                    <span className="flex items-center justify-center">
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Processing...
                    </span>
                  ) : (
                    <span className="flex items-center justify-center">
                      <span className="mr-2">{editingId ? "💾" : "➕"}</span>
                      {editingId ? "Update Password" : "Add Password"}
                    </span>
                  )}
                </button>

                {editingId && (
                  <button
                    type="button"
                    onClick={() => {
                      setEditingId(null);
                      setForm({ website: "", username: "", password: "" });
                    }}
                    className="px-6 py-3 bg-gray-500/20 hover:bg-gray-500/30 border border-gray-500/30 rounded-xl text-gray-300 font-semibold transition-all duration-300"
                  >
                    <span className="mr-2">❌</span> Cancel
                  </button>
                )}
              </div>
            </form>
          </div>

          {/* Password Table */}
          <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl overflow-hidden">
            <div className="p-6 border-b border-white/10">
              <h3 className="text-xl font-semibold flex items-center">
                <span className="mr-2">🗂️</span>
                Your Passwords ({passwords.length})
              </h3>
            </div>

            {passwords.length === 0 ? (
              <div className="p-12 text-center">
                <div className="w-24 h-24 bg-gradient-to-r from-purple-500/20 to-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <span className="text-4xl">🔐</span>
                </div>
                <h4 className="text-xl font-semibold text-gray-300 mb-2">No passwords yet</h4>
                <p className="text-gray-400 mb-6">Start building your secure vault by adding your first password above.</p>
                <div className="inline-flex items-center text-purple-400">
                  <span className="mr-2">✨</span>
                  Your passwords are encrypted and secure
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Website</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Username</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Password</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {passwords.map((password, index) => (
                      <tr
                        key={password._id}
                        className={`border-b border-white/10 hover:bg-white/5 transition-colors duration-200 ${
                          index % 2 === 0 ? 'bg-white/2' : ''
                        }`}
                      >
                        <td className="py-4 px-6">
                          <div className="flex items-center">
                            <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-500 rounded-lg flex items-center justify-center mr-3">
                              <span className="text-sm">🌐</span>
                            </div>
                            <span className="font-medium text-white">{password.website}</span>
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <span className="text-gray-300">{password.username}</span>
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex items-center space-x-3">
                            <span className="font-mono text-gray-300 bg-gray-800/50 px-3 py-1 rounded-lg">
                              {showPasswords[password._id] ? password.password : "••••••••••••"}
                            </span>
                            <div className="flex space-x-2">
                              <button
                                onClick={() => togglePasswordVisibility(password._id)}
                                className="p-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 transition-all duration-200 hover:scale-110"
                                title={showPasswords[password._id] ? "Hide password" : "Show password"}
                              >
                                {showPasswords[password._id] ? "🙈" : "👁️"}
                              </button>
                              <button
                                onClick={() => copyToClipboard(password.password)}
                                className="p-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg text-green-300 transition-all duration-200 hover:scale-110"
                                title="Copy to clipboard"
                              >
                                📋
                              </button>
                            </div>
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => handleEdit(password)}
                              className="px-4 py-2 bg-yellow-500/20 hover:bg-yellow-500/30 border border-yellow-500/30 rounded-lg text-yellow-300 font-semibold transition-all duration-200 transform hover:scale-105"
                            >
                              <span className="mr-1">✏️</span> Edit
                            </button>
                            <button
                              onClick={() => handleDelete(password._id)}
                              className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg text-red-300 font-semibold transition-all duration-200 transform hover:scale-105"
                            >
                              <span className="mr-1">🗑️</span> Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Change Password Modal */}
      <ChangePasswordModal
        isOpen={showChangePasswordModal}
        onClose={() => setShowChangePasswordModal(false)}
        onSuccess={() => {
          // Optionally refresh data or show success message
          console.log("Master password changed successfully");
        }}
      />
    </div>
  );
}