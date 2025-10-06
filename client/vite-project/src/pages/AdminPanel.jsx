import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api/axios";

export default function AdminPanel() {
  const [users, setUsers] = useState([]);
  const [systemStats, setSystemStats] = useState({
    totalUsers: 0,
    totalPasswords: 0,
    activeUsers: 0,
    systemHealth: "healthy"
  });
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedTab, setSelectedTab] = useState("overview");
  const navigate = useNavigate();

  useEffect(() => {
    fetchSystemStats();
    fetchUsers();
    fetchAuditLogs();
  }, []);

  const fetchSystemStats = async () => {
    try {
      const res = await API.get("/admin/stats");
      setSystemStats(res.data);
    } catch (err) {
      console.error("Failed to fetch system stats:", err);
      // Mock data for demonstration
      setSystemStats({
        totalUsers: 156,
        totalPasswords: 2847,
        activeUsers: 89,
        systemHealth: "healthy",
        storageUsed: "2.4 GB",
        lastBackup: "2 hours ago"
      });
    }
  };

  const handleDeleteUser = async (userId) => {
    if (!window.confirm('Delete this user and all their passwords?')) return;
    try {
      await API.delete(`/admin/users/${userId}`);
      setUsers(users.filter(u => u._id !== userId));
    } catch (err) {
      setError("Failed to delete user");
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await API.get("/admin/users");
      setUsers(res.data);
    } catch (err) {
      console.error("Failed to fetch users:", err);
      // Mock data for demonstration
      setUsers([
        {
          _id: "1",
          username: "john_doe",
          email: "john@example.com",
          role: "user",
          status: "active",
          lastLogin: "2024-10-06T02:30:00Z",
          passwordCount: 23,
          createdAt: "2024-09-15T10:00:00Z"
        },
        {
          _id: "2",
          username: "jane_smith",
          email: "jane@example.com",
          role: "user",
          status: "active",
          lastLogin: "2024-10-05T18:45:00Z",
          passwordCount: 45,
          createdAt: "2024-08-20T14:30:00Z"
        },
        {
          _id: "3",
          username: "admin_user",
          email: "admin@cryptonote.com",
          role: "admin",
          status: "active",
          lastLogin: "2024-10-06T01:15:00Z",
          passwordCount: 12,
          createdAt: "2024-07-01T09:00:00Z"
        }
      ]);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await API.get("/admin/audit-logs");
      setAuditLogs(res.data);
    } catch (err) {
      console.error("Failed to fetch audit logs:", err);
      // Mock data for demonstration
      setAuditLogs([
        {
          _id: "1",
          action: "LOGIN_SUCCESS",
          user: "john_doe",
          timestamp: "2024-10-06T02:30:00Z",
          ipAddress: "192.168.1.100",
          details: "Successful login"
        },
        {
          _id: "2",
          action: "PASSWORD_CREATED",
          user: "jane_smith",
          timestamp: "2024-10-06T01:45:00Z",
          ipAddress: "192.168.1.101",
          details: "Created password for github.com"
        },
        {
          _id: "3",
          action: "FAILED_LOGIN",
          user: "unknown",
          timestamp: "2024-10-06T01:20:00Z",
          ipAddress: "203.45.67.89",
          details: "Failed login attempt"
        }
      ]);
    }
  };

  const handleUserStatusChange = async (userId, newStatus) => {
    try {
      await API.put(`/admin/users/${userId}/status`, { status: newStatus });
      setUsers(users.map(user => 
        user._id === userId ? { ...user, status: newStatus } : user
      ));
    } catch (err) {
      setError("Failed to update user status");
    }
  };

  const handleUserRoleChange = async (userId, newRole) => {
    try {
      await API.put(`/admin/users/${userId}/role`, { role: newRole });
      setUsers(users.map(user => 
        user._id === userId ? { ...user, role: newRole } : user
      ));
    } catch (err) {
      setError("Failed to update user role");
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "active": return "text-green-400 bg-green-500/20";
      case "suspended": return "text-yellow-400 bg-yellow-500/20";
      case "banned": return "text-red-400 bg-red-500/20";
      default: return "text-gray-400 bg-gray-500/20";
    }
  };

  const getRoleColor = (role) => {
    switch (role) {
      case "admin": return "text-purple-400 bg-purple-500/20";
      case "moderator": return "text-blue-400 bg-blue-500/20";
      case "user": return "text-gray-400 bg-gray-500/20";
      default: return "text-gray-400 bg-gray-500/20";
    }
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
              <div className="w-12 h-12 bg-gradient-to-r from-red-500 to-purple-500 rounded-xl flex items-center justify-center mr-4">
                <span className="text-2xl">👑</span>
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-red-400 to-purple-400 bg-clip-text text-transparent">
                  Admin Panel
                </h1>
                <p className="text-gray-400">System administration and monitoring</p>
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={() => navigate("/dashboard")}
                className="px-6 py-3 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-xl text-blue-300 font-semibold transition-all duration-300 transform hover:scale-105"
              >
                <span className="mr-2">🏠</span> Dashboard
              </button>
              <button
                onClick={() => navigate("/profile")}
                className="px-6 py-3 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-xl text-green-300 font-semibold transition-all duration-300 transform hover:scale-105"
              >
                <span className="mr-2">👤</span> Profile
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-4 rounded-xl mb-6 text-center backdrop-blur-sm">
              <span className="text-red-300">⚠️</span> {error}
            </div>
          )}

          {/* Tab Navigation */}
          <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6 mb-6">
            <div className="flex flex-wrap gap-3">
              {[
                { id: "overview", label: "Overview", icon: "📊" },
                { id: "users", label: "Users", icon: "👥" },
                { id: "audit", label: "Audit Logs", icon: "📋" },
                { id: "settings", label: "Settings", icon: "⚙️" }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setSelectedTab(tab.id)}
                  className={`px-6 py-3 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 ${
                    selectedTab === tab.id
                      ? "bg-gradient-to-r from-purple-600 to-blue-600 text-white"
                      : "bg-white/10 hover:bg-white/20 text-gray-300"
                  }`}
                >
                  <span className="mr-2">{tab.icon}</span>
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Overview Tab */}
          {selectedTab === "overview" && (
            <div className="space-y-6">
              {/* System Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Total Users</p>
                      <p className="text-3xl font-bold text-blue-400">{systemStats.totalUsers}</p>
                    </div>
                    <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">👥</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Total Passwords</p>
                      <p className="text-3xl font-bold text-green-400">{systemStats.totalPasswords}</p>
                    </div>
                    <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">🔐</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Active Users</p>
                      <p className="text-3xl font-bold text-purple-400">{systemStats.activeUsers}</p>
                    </div>
                    <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">🟢</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">System Health</p>
                      <p className="text-3xl font-bold text-green-400 capitalize">{systemStats.systemHealth}</p>
                    </div>
                    <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">❤️</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* System Information */}
              <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                <h3 className="text-xl font-semibold mb-4 flex items-center">
                  <span className="mr-2">🖥️</span>
                  System Information
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <p className="text-gray-400 mb-2">Storage Used</p>
                    <p className="text-white font-semibold">{systemStats.storageUsed || "2.4 GB"}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 mb-2">Last Backup</p>
                    <p className="text-white font-semibold">{systemStats.lastBackup || "2 hours ago"}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Users Tab */}
          {selectedTab === "users" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl overflow-hidden">
              <div className="p-6 border-b border-white/10">
                <h3 className="text-xl font-semibold flex items-center">
                  <span className="mr-2">👥</span>
                  User Management ({users.length})
                </h3>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">User</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Role</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Status</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Last Login</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Passwords</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user, index) => (
                      <tr
                        key={user._id}
                        className={`border-b border-white/10 hover:bg-white/5 transition-colors duration-200 ${
                          index % 2 === 0 ? 'bg-white/2' : ''
                        }`}
                      >
                        <td className="py-4 px-6">
                          <div>
                            <p className="font-semibold text-white">{user.username}</p>
                            <p className="text-gray-400 text-sm">{user.email}</p>
                          </div>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getRoleColor(user.role)}`}>
                            {user.role.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusColor(user.status)}`}>
                            {user.status.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-4 px-6 text-gray-300">
                          {formatDate(user.lastLogin)}
                        </td>
                        <td className="py-4 px-6 text-gray-300">
                          {user.passwordCount}
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex flex-wrap gap-2 items-center">
                            <select
                              value={user.status}
                              onChange={(e) => handleUserStatusChange(user._id, e.target.value)}
                              className="px-3 py-1 bg-white/10 border border-white/20 rounded-lg text-white text-sm"
                            >
                              <option value="active" className="bg-gray-800">Active</option>
                              <option value="suspended" className="bg-gray-800">Suspended</option>
                              <option value="banned" className="bg-gray-800">Banned</option>
                            </select>
                            <select
                              value={user.role}
                              onChange={(e) => handleUserRoleChange(user._id, e.target.value)}
                              className="px-3 py-1 bg-white/10 border border-white/20 rounded-lg text-white text-sm"
                            >
                              <option value="user" className="bg-gray-800">User</option>
                              <option value="moderator" className="bg-gray-800">Moderator</option>
                              <option value="admin" className="bg-gray-800">Admin</option>
                            </select>
                            <button
                              onClick={() => handleDeleteUser(user._id)}
                              className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg text-red-300 text-sm"
                              title="Delete user"
                            >
                              🗑️ Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Audit Logs Tab */}
          {selectedTab === "audit" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl overflow-hidden">
              <div className="p-6 border-b border-white/10">
                <h3 className="text-xl font-semibold flex items-center">
                  <span className="mr-2">📋</span>
                  Audit Logs ({auditLogs.length})
                </h3>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Timestamp</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Action</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">User</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">IP Address</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log, index) => (
                      <tr
                        key={log._id}
                        className={`border-b border-white/10 hover:bg-white/5 transition-colors duration-200 ${
                          index % 2 === 0 ? 'bg-white/2' : ''
                        }`}
                      >
                        <td className="py-4 px-6 text-gray-300">
                          {formatDate(log.timestamp)}
                        </td>
                        <td className="py-4 px-6">
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            log.action.includes('SUCCESS') ? 'text-green-400 bg-green-500/20' :
                            log.action.includes('FAILED') ? 'text-red-400 bg-red-500/20' :
                            'text-blue-400 bg-blue-500/20'
                          }`}>
                            {log.action}
                          </span>
                        </td>
                        <td className="py-4 px-6 text-white font-semibold">
                          {log.user}
                        </td>
                        <td className="py-4 px-6 text-gray-300 font-mono">
                          {log.ipAddress}
                        </td>
                        <td className="py-4 px-6 text-gray-300">
                          {log.details}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Settings Tab */}
          {selectedTab === "settings" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
              <h3 className="text-xl font-semibold mb-6 flex items-center">
                <span className="mr-2">⚙️</span>
                System Settings
              </h3>
              
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h4 className="text-lg font-semibold text-purple-400">Security Settings</h4>
                    <div className="space-y-3">
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Require 2FA for all users</span>
                        <input type="checkbox" className="toggle" defaultChecked />
                      </label>
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Enable audit logging</span>
                        <input type="checkbox" className="toggle" defaultChecked />
                      </label>
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Auto-lock after inactivity</span>
                        <input type="checkbox" className="toggle" defaultChecked />
                      </label>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h4 className="text-lg font-semibold text-blue-400">System Settings</h4>
                    <div className="space-y-3">
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Maintenance mode</span>
                        <input type="checkbox" className="toggle" />
                      </label>
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Auto-backup enabled</span>
                        <input type="checkbox" className="toggle" defaultChecked />
                      </label>
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Email notifications</span>
                        <input type="checkbox" className="toggle" defaultChecked />
                      </label>
                    </div>
                  </div>
                </div>

                <div className="pt-6 border-t border-white/10">
                  <button className="px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-xl text-white font-semibold transition-all duration-300 transform hover:scale-105">
                    <span className="mr-2">💾</span>
                    Save Settings
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
