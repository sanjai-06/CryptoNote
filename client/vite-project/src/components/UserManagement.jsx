import { useState } from "react";

export default function UserManagement() {
  const [users, setUsers] = useState([
    { id: 1, username: "john_doe", email: "john@company.com", role: "user", status: "active", lastLogin: "2024-10-06T08:30:00Z", mfaEnabled: true, loginAttempts: 0 },
    { id: 2, username: "jane_admin", email: "jane@company.com", role: "admin", status: "active", lastLogin: "2024-10-06T07:15:00Z", mfaEnabled: true, loginAttempts: 0 },
    { id: 3, username: "bob_user", email: "bob@company.com", role: "user", status: "suspended", lastLogin: "2024-10-05T14:22:00Z", mfaEnabled: false, loginAttempts: 5 }
  ]);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterRole, setFilterRole] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");

  const [newUser, setNewUser] = useState({
    username: "",
    email: "",
    password: "",
    role: "user",
    mfaRequired: false
  });

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = filterRole === "all" || user.role === filterRole;
    const matchesStatus = filterStatus === "all" || user.status === filterStatus;
    return matchesSearch && matchesRole && matchesStatus;
  });

  const handleCreateUser = () => {
    const user = {
      id: users.length + 1,
      ...newUser,
      status: "active",
      lastLogin: null,
      mfaEnabled: newUser.mfaRequired,
      loginAttempts: 0
    };
    setUsers([...users, user]);
    setNewUser({ username: "", email: "", password: "", role: "user", mfaRequired: false });
    setShowCreateModal(false);
  };

  const handleStatusChange = (userId, newStatus) => {
    setUsers(users.map(user => 
      user.id === userId ? { ...user, status: newStatus } : user
    ));
  };

  const handleRoleChange = (userId, newRole) => {
    setUsers(users.map(user => 
      user.id === userId ? { ...user, role: newRole } : user
    ));
  };

  const handleDeleteUser = (userId) => {
    if (window.confirm("Are you sure you want to delete this user?")) {
      setUsers(users.filter(user => user.id !== userId));
    }
  };

  const resetUserPassword = (userId) => {
    // In real implementation, this would generate a temporary password
    alert("Password reset email sent to user");
  };

  const toggleMFA = (userId) => {
    setUsers(users.map(user => 
      user.id === userId ? { ...user, mfaEnabled: !user.mfaEnabled } : user
    ));
  };

  const getRoleColor = (role) => {
    switch (role) {
      case "admin": return "bg-purple-500/20 text-purple-300";
      case "moderator": return "bg-blue-500/20 text-blue-300";
      case "user": return "bg-gray-500/20 text-gray-300";
      default: return "bg-gray-500/20 text-gray-300";
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "active": return "bg-green-500/20 text-green-300";
      case "suspended": return "bg-yellow-500/20 text-yellow-300";
      case "banned": return "bg-red-500/20 text-red-300";
      case "pending": return "bg-blue-500/20 text-blue-300";
      default: return "bg-gray-500/20 text-gray-300";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Actions */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg text-green-300 font-semibold transition-all duration-300"
          >
            <span className="mr-2">➕</span> Create User
          </button>
          <button className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 font-semibold transition-all duration-300">
            <span className="mr-2">📥</span> Import Users
          </button>
          <button className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg text-purple-300 font-semibold transition-all duration-300">
            <span className="mr-2">📊</span> Export Report
          </button>
        </div>

        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            placeholder="Search users..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="px-4 py-2 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
          />
          <select
            value={filterRole}
            onChange={(e) => setFilterRole(e.target.value)}
            className="px-3 py-2 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
          >
            <option value="all" className="bg-gray-800">All Roles</option>
            <option value="admin" className="bg-gray-800">Admin</option>
            <option value="moderator" className="bg-gray-800">Moderator</option>
            <option value="user" className="bg-gray-800">User</option>
          </select>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-3 py-2 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
          >
            <option value="all" className="bg-gray-800">All Status</option>
            <option value="active" className="bg-gray-800">Active</option>
            <option value="suspended" className="bg-gray-800">Suspended</option>
            <option value="banned" className="bg-gray-800">Banned</option>
          </select>
        </div>
      </div>

      {/* User Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <span className="text-lg">👥</span>
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{users.length}</p>
              <p className="text-gray-400 text-sm">Total Users</p>
            </div>
          </div>
        </div>
        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
              <span className="text-lg">✅</span>
            </div>
            <div>
              <p className="text-2xl font-bold text-green-400">{users.filter(u => u.status === 'active').length}</p>
              <p className="text-gray-400 text-sm">Active Users</p>
            </div>
          </div>
        </div>
        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
              <span className="text-lg">👑</span>
            </div>
            <div>
              <p className="text-2xl font-bold text-purple-400">{users.filter(u => u.role === 'admin').length}</p>
              <p className="text-gray-400 text-sm">Administrators</p>
            </div>
          </div>
        </div>
        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
              <span className="text-lg">🔐</span>
            </div>
            <div>
              <p className="text-2xl font-bold text-orange-400">{users.filter(u => u.mfaEnabled).length}</p>
              <p className="text-gray-400 text-sm">MFA Enabled</p>
            </div>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-white/5">
              <tr>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">User</th>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">Role</th>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">Status</th>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">MFA</th>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">Last Login</th>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">Failed Attempts</th>
                <th className="py-4 px-6 text-left text-gray-300 font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user, index) => (
                <tr key={user.id} className={`border-b border-white/10 hover:bg-white/5 transition-colors ${index % 2 === 0 ? 'bg-white/2' : ''}`}>
                  <td className="py-4 px-6">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 bg-gradient-to-r from-purple-500 to-blue-500 rounded-full flex items-center justify-center">
                        <span className="text-sm font-bold">{user.username[0].toUpperCase()}</span>
                      </div>
                      <div>
                        <p className="font-semibold text-white">{user.username}</p>
                        <p className="text-gray-400 text-sm">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="py-4 px-6">
                    <select
                      value={user.role}
                      onChange={(e) => handleRoleChange(user.id, e.target.value)}
                      className={`px-3 py-1 rounded-full text-xs font-semibold border-0 ${getRoleColor(user.role)}`}
                    >
                      <option value="user" className="bg-gray-800">User</option>
                      <option value="moderator" className="bg-gray-800">Moderator</option>
                      <option value="admin" className="bg-gray-800">Admin</option>
                    </select>
                  </td>
                  <td className="py-4 px-6">
                    <select
                      value={user.status}
                      onChange={(e) => handleStatusChange(user.id, e.target.value)}
                      className={`px-3 py-1 rounded-full text-xs font-semibold border-0 ${getStatusColor(user.status)}`}
                    >
                      <option value="active" className="bg-gray-800">Active</option>
                      <option value="suspended" className="bg-gray-800">Suspended</option>
                      <option value="banned" className="bg-gray-800">Banned</option>
                    </select>
                  </td>
                  <td className="py-4 px-6">
                    <button
                      onClick={() => toggleMFA(user.id)}
                      className={`text-lg ${user.mfaEnabled ? 'text-green-400' : 'text-red-400'}`}
                      title={user.mfaEnabled ? 'MFA Enabled' : 'MFA Disabled'}
                    >
                      {user.mfaEnabled ? '✅' : '❌'}
                    </button>
                  </td>
                  <td className="py-4 px-6 text-gray-300">
                    {user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}
                  </td>
                  <td className="py-4 px-6">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                      user.loginAttempts > 3 ? 'bg-red-500/20 text-red-300' : 
                      user.loginAttempts > 0 ? 'bg-yellow-500/20 text-yellow-300' : 
                      'bg-green-500/20 text-green-300'
                    }`}>
                      {user.loginAttempts}
                    </span>
                  </td>
                  <td className="py-4 px-6">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => setSelectedUser(user)}
                        className="p-2 bg-blue-500/20 hover:bg-blue-500/30 rounded-lg text-blue-300 transition-all duration-200"
                        title="Edit User"
                      >
                        ✏️
                      </button>
                      <button
                        onClick={() => resetUserPassword(user.id)}
                        className="p-2 bg-yellow-500/20 hover:bg-yellow-500/30 rounded-lg text-yellow-300 transition-all duration-200"
                        title="Reset Password"
                      >
                        🔑
                      </button>
                      <button
                        onClick={() => handleDeleteUser(user.id)}
                        className="p-2 bg-red-500/20 hover:bg-red-500/30 rounded-lg text-red-300 transition-all duration-200"
                        title="Delete User"
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-white/20 rounded-2xl p-6 w-full max-w-md mx-4">
            <h3 className="text-xl font-semibold mb-4 text-white">Create New User</h3>
            <div className="space-y-4">
              <input
                type="text"
                placeholder="Username"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
              />
              <input
                type="email"
                placeholder="Email"
                value={newUser.email}
                onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
              />
              <input
                type="password"
                placeholder="Temporary Password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
              />
              <select
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
              >
                <option value="user" className="bg-gray-800">User</option>
                <option value="moderator" className="bg-gray-800">Moderator</option>
                <option value="admin" className="bg-gray-800">Admin</option>
              </select>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={newUser.mfaRequired}
                  onChange={(e) => setNewUser({ ...newUser, mfaRequired: e.target.checked })}
                  className="w-4 h-4 text-purple-600 rounded"
                />
                <span className="text-gray-300">Require MFA</span>
              </label>
            </div>
            <div className="flex space-x-3 mt-6">
              <button
                onClick={handleCreateUser}
                className="flex-1 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white font-semibold transition-all duration-300"
              >
                Create User
              </button>
              <button
                onClick={() => setShowCreateModal(false)}
                className="flex-1 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-white font-semibold transition-all duration-300"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
