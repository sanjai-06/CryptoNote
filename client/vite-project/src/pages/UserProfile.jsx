import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api/axios";
import ChangePasswordModal from "../components/ChangePasswordModal";
import TwoFactorSetup from "../components/TwoFactorSetup";

export default function UserProfile() {
  const [profile, setProfile] = useState({
    username: "",
    email: "",
    firstName: "",
    lastName: "",
    avatar: "",
    twoFactorEnabled: false,
    emailNotifications: true,
    securityAlerts: true,
    theme: "dark"
  });
  const [stats, setStats] = useState({
    totalPasswords: 0,
    categoriesUsed: 0,
    lastLogin: "",
    accountCreated: "",
    loginHistory: []
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [showChangePasswordModal, setShowChangePasswordModal] = useState(false);
  const [selectedTab, setSelectedTab] = useState("profile");
  const [isEditing, setIsEditing] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // If backend forced 2FA setup, send user to Security tab
    if (sessionStorage.getItem("force2FASetup") === "1") {
      setSelectedTab("security");
      sessionStorage.removeItem("force2FASetup");
    }
    fetchProfile();
    fetchStats();
  }, []);

  const fetchProfile = async () => {
    try {
      const res = await API.get("/user/profile");
      setProfile(res.data);
      setError("");
    } catch (err) {
      // Fallback to /auth/me for minimal info if detailed profile fails
      try {
        const me = await API.get("/auth/me");
        setProfile((prev) => ({
          ...prev,
          username: me.data.username || prev.username,
          email: me.data.email || prev.email,
          firstName: me.data.firstName || prev.firstName,
          lastName: me.data.lastName || prev.lastName,
          twoFactorEnabled: !!me.data.twoFactorEnabled
        }));
        setError("");
      } catch (e2) {
        setError(err?.response?.data?.message || "Failed to fetch profile. Please login and try again.");
      }
    }
  };

  const fetchStats = async () => {
    try {
      const res = await API.get("/user/stats");
      setStats(res.data);
    } catch (err) {
      setError((prev) => prev || err?.response?.data?.message || "Failed to fetch stats");
    }
  };

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setSuccess("");

    try {
      const res = await API.put("/user/profile", profile);
      setProfile(res.data);
      setSuccess("Profile updated successfully!");
      setIsEditing(false);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to update profile");
    } finally {
      setLoading(false);
    }
  };


  const handleDeleteAccount = async () => {
    if (!window.confirm("Are you sure you want to delete your account? This action cannot be undone.")) {
      return;
    }

    const confirmation = window.prompt("Type 'DELETE' to confirm account deletion:");
    if (confirmation !== "DELETE") {
      return;
    }

    try {
      await API.delete("/user/account");
      localStorage.removeItem("token");
      navigate("/register");
    } catch (err) {
      setError("Failed to delete account");
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getDeviceIcon = (device) => {
    if (device.includes("iPhone") || device.includes("Android")) return "📱";
    if (device.includes("iPad") || device.includes("Tablet")) return "📱";
    if (device.includes("Mac")) return "💻";
    if (device.includes("Windows")) return "🖥️";
    return "🌐";
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white">
      {/* Animated background */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
      </div>

      <div className="relative z-10 p-6">
        <div className="w-full max-w-6xl mx-auto">
          {/* Header */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
            <div className="flex items-center mb-4 md:mb-0">
              <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-purple-500 rounded-xl flex items-center justify-center mr-4">
                {profile.avatar ? (
                  <img src={profile.avatar} alt="Avatar" className="w-full h-full rounded-xl object-cover" />
                ) : (
                  <span className="text-2xl">👤</span>
                )}
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                  {profile.firstName || profile.username}'s Profile
                </h1>
                <p className="text-gray-400">Manage your account and preferences</p>
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
                onClick={() => setShowChangePasswordModal(true)}
                className="px-6 py-3 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-xl text-purple-300 font-semibold transition-all duration-300 transform hover:scale-105"
              >
                <span className="mr-2">🔐</span> Change Password
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-4 rounded-xl mb-6 text-center backdrop-blur-sm">
              <span className="text-red-300">⚠️</span> {error}
            </div>
          )}

          {success && (
            <div className="bg-green-500/20 border border-green-500/30 text-green-200 p-4 rounded-xl mb-6 text-center backdrop-blur-sm">
              <span className="text-green-300">✅</span> {success}
            </div>
          )}

          {/* Tab Navigation */}
          <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6 mb-6">
            <div className="flex flex-wrap gap-3">
              {[
                { id: "profile", label: "Profile", icon: "👤" },
                { id: "security", label: "Security", icon: "🔒" },
                { id: "preferences", label: "Preferences", icon: "⚙️" },
                { id: "activity", label: "Activity", icon: "📊" }
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

          {/* Profile Tab */}
          {selectedTab === "profile" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-xl font-semibold flex items-center">
                  <span className="mr-2">👤</span>
                  Personal Information
                </h3>
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-xl text-blue-300 font-semibold transition-all duration-300"
                >
                  <span className="mr-2">{isEditing ? "❌" : "✏️"}</span>
                  {isEditing ? "Cancel" : "Edit"}
                </button>
              </div>

              <form onSubmit={handleProfileUpdate} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="block text-gray-300 text-sm font-semibold mb-2">Username</label>
                    <input
                      type="text"
                      value={profile.username}
                      onChange={(e) => setProfile({ ...profile, username: e.target.value })}
                      disabled={!isEditing}
                      className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300 disabled:opacity-50"
                    />
                  </div>

                  <div>
                    <label className="block text-gray-300 text-sm font-semibold mb-2">Email</label>
                    <input
                      type="email"
                      value={profile.email}
                      onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                      disabled={!isEditing}
                      className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300 disabled:opacity-50"
                    />
                  </div>

                  <div>
                    <label className="block text-gray-300 text-sm font-semibold mb-2">First Name</label>
                    <input
                      type="text"
                      value={profile.firstName}
                      onChange={(e) => setProfile({ ...profile, firstName: e.target.value })}
                      disabled={!isEditing}
                      className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300 disabled:opacity-50"
                    />
                  </div>

                  <div>
                    <label className="block text-gray-300 text-sm font-semibold mb-2">Last Name</label>
                    <input
                      type="text"
                      value={profile.lastName}
                      onChange={(e) => setProfile({ ...profile, lastName: e.target.value })}
                      disabled={!isEditing}
                      className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300 disabled:opacity-50"
                    />
                  </div>
                </div>

                {isEditing && (
                  <div className="flex gap-3">
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 rounded-xl text-white font-semibold transition-all duration-300 transform hover:scale-105 disabled:scale-100"
                    >
                      {loading ? (
                        <span className="flex items-center">
                          <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          Saving...
                        </span>
                      ) : (
                        <span className="flex items-center">
                          <span className="mr-2">💾</span>
                          Save Changes
                        </span>
                      )}
                    </button>
                  </div>
                )}
              </form>
            </div>
          )}

          {/* Security Tab */}
          {selectedTab === "security" && (
            <div className="space-y-6">
              {/* Two-Factor Authentication */}
              <TwoFactorSetup 
                user={profile} 
                onUpdate={setProfile}
              />

              {/* Password Security */}
              <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                <h3 className="text-xl font-semibold mb-4 flex items-center">
                  <span className="mr-2">🔑</span>
                  Password Security
                </h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-300 mb-2">Master Password</p>
                      <p className="text-gray-400 text-sm">Last changed: 30 days ago</p>
                    </div>
                    <button
                      onClick={() => setShowChangePasswordModal(true)}
                      className="px-6 py-3 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-xl text-purple-300 font-semibold transition-all duration-300 transform hover:scale-105"
                    >
                      <span className="mr-2">🔐</span>
                      Change Password
                    </button>
                  </div>
                </div>
              </div>

              {/* Danger Zone */}
              <div className="bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
                <h3 className="text-xl font-semibold mb-4 flex items-center text-red-400">
                  <span className="mr-2">⚠️</span>
                  Danger Zone
                </h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-300 mb-2">Delete Account</p>
                      <p className="text-gray-400 text-sm">Permanently delete your account and all data</p>
                    </div>
                    <button
                      onClick={handleDeleteAccount}
                      className="px-6 py-3 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-xl text-red-300 font-semibold transition-all duration-300 transform hover:scale-105"
                    >
                      <span className="mr-2">🗑️</span>
                      Delete Account
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Preferences Tab */}
          {selectedTab === "preferences" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
              <h3 className="text-xl font-semibold mb-6 flex items-center">
                <span className="mr-2">⚙️</span>
                Preferences
              </h3>

              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h4 className="text-lg font-semibold text-purple-400">Notifications</h4>
                    <div className="space-y-3">
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Email notifications</span>
                        <input
                          type="checkbox"
                          checked={profile.emailNotifications}
                          onChange={(e) => setProfile({ ...profile, emailNotifications: e.target.checked })}
                          className="toggle"
                        />
                      </label>
                      <label className="flex items-center justify-between">
                        <span className="text-gray-300">Security alerts</span>
                        <input
                          type="checkbox"
                          checked={profile.securityAlerts}
                          onChange={(e) => setProfile({ ...profile, securityAlerts: e.target.checked })}
                          className="toggle"
                        />
                      </label>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h4 className="text-lg font-semibold text-blue-400">Appearance</h4>
                    <div className="space-y-3">
                      <label className="block">
                        <span className="text-gray-300 mb-2 block">Theme</span>
                        <select
                          value={profile.theme}
                          onChange={(e) => setProfile({ ...profile, theme: e.target.value })}
                          className="w-full p-3 bg-white/10 border border-white/20 rounded-xl text-white"
                        >
                          <option value="dark" className="bg-gray-800">Dark</option>
                          <option value="light" className="bg-gray-800">Light</option>
                          <option value="auto" className="bg-gray-800">Auto</option>
                        </select>
                      </label>
                    </div>
                  </div>
                </div>

                <div className="pt-6 border-t border-white/10">
                  <button
                    onClick={handleProfileUpdate}
                    className="px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-xl text-white font-semibold transition-all duration-300 transform hover:scale-105"
                  >
                    <span className="mr-2">💾</span>
                    Save Preferences
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Activity Tab */}
          {selectedTab === "activity" && (
            <div className="space-y-6">
              {/* Account Stats */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Total Passwords</p>
                      <p className="text-3xl font-bold text-blue-400">{stats.totalPasswords}</p>
                    </div>
                    <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">🔐</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Categories Used</p>
                      <p className="text-3xl font-bold text-green-400">{stats.categoriesUsed}</p>
                    </div>
                    <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">📁</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Last Login</p>
                      <p className="text-lg font-bold text-purple-400">{formatDate(stats.lastLogin).split(',')[0]}</p>
                    </div>
                    <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">🕐</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-gray-400 text-sm">Member Since</p>
                      <p className="text-lg font-bold text-yellow-400">{formatDate(stats.accountCreated).split(',')[0]}</p>
                    </div>
                    <div className="w-12 h-12 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                      <span className="text-2xl">🎉</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Login History */}
              <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-2xl overflow-hidden">
                <div className="p-6 border-b border-white/10">
                  <h3 className="text-xl font-semibold flex items-center">
                    <span className="mr-2">📊</span>
                    Recent Login Activity
                  </h3>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-white/5">
                      <tr>
                        <th className="py-4 px-6 text-left text-gray-300 font-semibold">Date & Time</th>
                        <th className="py-4 px-6 text-left text-gray-300 font-semibold">Device</th>
                        <th className="py-4 px-6 text-left text-gray-300 font-semibold">IP Address</th>
                        <th className="py-4 px-6 text-left text-gray-300 font-semibold">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.loginHistory.map((login, index) => (
                        <tr
                          key={index}
                          className={`border-b border-white/10 hover:bg-white/5 transition-colors duration-200 ${
                            index % 2 === 0 ? 'bg-white/2' : ''
                          }`}
                        >
                          <td className="py-4 px-6 text-gray-300">
                            {formatDate(login.timestamp)}
                          </td>
                          <td className="py-4 px-6">
                            <div className="flex items-center">
                              <span className="text-lg mr-2">{getDeviceIcon(login.device)}</span>
                              <span className="text-white">{login.device}</span>
                            </div>
                          </td>
                          <td className="py-4 px-6 text-gray-300 font-mono">
                            {login.ipAddress}
                          </td>
                          <td className="py-4 px-6">
                            <span className="px-3 py-1 rounded-full text-xs font-semibold text-green-400 bg-green-500/20">
                              SUCCESS
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Change Password Modal */}
      <ChangePasswordModal
        isOpen={showChangePasswordModal}
        onClose={() => setShowChangePasswordModal(false)}
        onSuccess={() => {
          setSuccess("Master password changed successfully");
          setShowChangePasswordModal(false);
        }}
      />
    </div>
  );
}
