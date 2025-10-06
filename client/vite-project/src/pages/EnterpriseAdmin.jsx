import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api/axios";

export default function EnterpriseAdmin() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [users, setUsers] = useState([]);
  const [systemMetrics, setSystemMetrics] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [securityAlerts, setSecurityAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchSystemData();
  }, []);

  const fetchSystemData = async () => {
    setLoading(true);
    try {
      // Mock data - replace with actual API calls
      setSystemMetrics({
        totalUsers: 1247,
        activeUsers: 892,
        totalPasswords: 15634,
        systemHealth: 98.5,
        cpuUsage: 45,
        memoryUsage: 67,
        diskUsage: 34,
        networkTraffic: 2.3
      });

      setUsers([
        { id: 1, username: "john_doe", email: "john@company.com", role: "user", status: "active", lastLogin: "2024-10-06T08:30:00Z", mfaEnabled: true },
        { id: 2, username: "jane_admin", email: "jane@company.com", role: "admin", status: "active", lastLogin: "2024-10-06T07:15:00Z", mfaEnabled: true },
        { id: 3, username: "bob_user", email: "bob@company.com", role: "user", status: "suspended", lastLogin: "2024-10-05T14:22:00Z", mfaEnabled: false }
      ]);

      setSecurityAlerts([
        { id: 1, type: "warning", message: "Multiple failed login attempts detected", timestamp: "2024-10-06T08:45:00Z", severity: "medium" },
        { id: 2, type: "info", message: "System backup completed successfully", timestamp: "2024-10-06T06:00:00Z", severity: "low" },
        { id: 3, type: "critical", message: "Suspicious API access pattern detected", timestamp: "2024-10-06T09:12:00Z", severity: "high" }
      ]);

    } catch (error) {
      console.error("Failed to fetch system data:", error);
    } finally {
      setLoading(false);
    }
  };

  const menuItems = [
    { id: "dashboard", label: "Dashboard", icon: "📊", description: "System overview and metrics" },
    { id: "users", label: "User Management", icon: "👥", description: "Manage user accounts and permissions" },
    { id: "security", label: "Security Policies", icon: "🔒", description: "Configure security settings" },
    { id: "audit", label: "Audit Logs", icon: "📋", description: "View system activity logs" },
    { id: "settings", label: "System Settings", icon: "⚙️", description: "Configure system parameters" },
    { id: "integrations", label: "Integrations", icon: "🔗", description: "Manage external services" },
    { id: "notifications", label: "Notifications", icon: "🔔", description: "Configure alerts and notifications" }
  ];

  const MetricCard = ({ title, value, unit, trend, color, icon }) => (
    <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6 hover:bg-white/10 transition-all duration-300">
      <div className="flex items-center justify-between mb-4">
        <div className={`w-12 h-12 ${color} rounded-xl flex items-center justify-center`}>
          <span className="text-2xl">{icon}</span>
        </div>
        {trend && (
          <span className={`text-sm font-semibold ${trend > 0 ? 'text-green-400' : 'text-red-400'}`}>
            {trend > 0 ? '↗' : '↘'} {Math.abs(trend)}%
          </span>
        )}
      </div>
      <h3 className="text-gray-400 text-sm mb-2">{title}</h3>
      <p className="text-3xl font-bold text-white">
        {value}<span className="text-lg text-gray-400 ml-1">{unit}</span>
      </p>
    </div>
  );

  const SecurityAlert = ({ alert }) => {
    const getAlertColor = (severity) => {
      switch (severity) {
        case "high": return "border-red-500/50 bg-red-500/10 text-red-300";
        case "medium": return "border-yellow-500/50 bg-yellow-500/10 text-yellow-300";
        case "low": return "border-blue-500/50 bg-blue-500/10 text-blue-300";
        default: return "border-gray-500/50 bg-gray-500/10 text-gray-300";
      }
    };

    const getAlertIcon = (type) => {
      switch (type) {
        case "critical": return "🚨";
        case "warning": return "⚠️";
        case "info": return "ℹ️";
        default: return "📢";
      }
    };

    return (
      <div className={`border rounded-lg p-4 ${getAlertColor(alert.severity)}`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-3">
            <span className="text-xl">{getAlertIcon(alert.type)}</span>
            <div>
              <p className="font-semibold">{alert.message}</p>
              <p className="text-sm opacity-75 mt-1">
                {new Date(alert.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
          <button className="text-sm opacity-75 hover:opacity-100">Dismiss</button>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white flex">
      {/* Sidebar */}
      <div className={`${sidebarCollapsed ? 'w-16' : 'w-64'} transition-all duration-300 bg-black/20 backdrop-blur-lg border-r border-white/10`}>
        <div className="p-6">
          <div className="flex items-center justify-between mb-8">
            {!sidebarCollapsed && (
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">
                  Enterprise Admin
                </h1>
                <p className="text-gray-400 text-sm">System Management</p>
              </div>
            )}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-2 hover:bg-white/10 rounded-lg transition-colors"
            >
              {sidebarCollapsed ? "→" : "←"}
            </button>
          </div>

          <nav className="space-y-2">
            {menuItems.map(item => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center space-x-3 p-3 rounded-lg transition-all duration-200 group ${
                  activeTab === item.id 
                    ? 'bg-gradient-to-r from-purple-600/50 to-blue-600/50 text-white' 
                    : 'hover:bg-white/10 text-gray-300'
                }`}
                title={sidebarCollapsed ? item.description : ''}
              >
                <span className="text-xl">{item.icon}</span>
                {!sidebarCollapsed && (
                  <div className="text-left">
                    <p className="font-semibold">{item.label}</p>
                    <p className="text-xs opacity-75">{item.description}</p>
                  </div>
                )}
              </button>
            ))}
          </nav>
        </div>

        {!sidebarCollapsed && (
          <div className="absolute bottom-6 left-6 right-6">
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <div className="flex items-center space-x-3 mb-3">
                <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                  <span className="text-sm">✓</span>
                </div>
                <div>
                  <p className="font-semibold text-sm">System Status</p>
                  <p className="text-xs text-green-400">All systems operational</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="p-6">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h2 className="text-3xl font-bold">
                {menuItems.find(item => item.id === activeTab)?.label}
              </h2>
              <p className="text-gray-400">
                {menuItems.find(item => item.id === activeTab)?.description}
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => navigate("/dashboard")}
                className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 font-semibold transition-all duration-300"
              >
                <span className="mr-2">🏠</span> Dashboard
              </button>
              <div className="w-10 h-10 bg-gradient-to-r from-purple-500 to-blue-500 rounded-full flex items-center justify-center">
                <span className="text-sm font-bold">A</span>
              </div>
            </div>
          </div>

          {/* Dashboard Tab */}
          {activeTab === "dashboard" && (
            <div className="space-y-6">
              {/* System Metrics */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <MetricCard
                  title="Total Users"
                  value={systemMetrics.totalUsers}
                  trend={5.2}
                  color="bg-blue-500/20"
                  icon="👥"
                />
                <MetricCard
                  title="Active Users"
                  value={systemMetrics.activeUsers}
                  trend={2.1}
                  color="bg-green-500/20"
                  icon="🟢"
                />
                <MetricCard
                  title="Total Passwords"
                  value={systemMetrics.totalPasswords}
                  trend={8.7}
                  color="bg-purple-500/20"
                  icon="🔐"
                />
                <MetricCard
                  title="System Health"
                  value={systemMetrics.systemHealth}
                  unit="%"
                  trend={0.3}
                  color="bg-emerald-500/20"
                  icon="❤️"
                />
              </div>

              {/* Resource Usage */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-4 flex items-center">
                    <span className="mr-2">📈</span> Resource Usage
                  </h3>
                  <div className="space-y-4">
                    {[
                      { label: "CPU Usage", value: systemMetrics.cpuUsage, color: "bg-blue-500" },
                      { label: "Memory Usage", value: systemMetrics.memoryUsage, color: "bg-purple-500" },
                      { label: "Disk Usage", value: systemMetrics.diskUsage, color: "bg-green-500" }
                    ].map(metric => (
                      <div key={metric.label}>
                        <div className="flex justify-between text-sm mb-2">
                          <span className="text-gray-300">{metric.label}</span>
                          <span className="text-white font-semibold">{metric.value}%</span>
                        </div>
                        <div className="w-full bg-gray-700 rounded-full h-2">
                          <div
                            className={`${metric.color} h-2 rounded-full transition-all duration-500`}
                            style={{ width: `${metric.value}%` }}
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-4 flex items-center">
                    <span className="mr-2">🚨</span> Security Alerts
                  </h3>
                  <div className="space-y-3 max-h-64 overflow-y-auto">
                    {securityAlerts.map(alert => (
                      <SecurityAlert key={alert.id} alert={alert} />
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* User Management Tab */}
          {activeTab === "users" && (
            <div className="space-y-6">
              <div className="flex justify-between items-center">
                <div className="flex space-x-4">
                  <button className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg text-green-300 font-semibold transition-all duration-300">
                    <span className="mr-2">➕</span> Add User
                  </button>
                  <button className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 font-semibold transition-all duration-300">
                    <span className="mr-2">📥</span> Import Users
                  </button>
                </div>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    placeholder="Search users..."
                    className="px-4 py-2 bg-white/5 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                  />
                  <button className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-gray-300 transition-all duration-300">
                    🔍
                  </button>
                </div>
              </div>

              <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl overflow-hidden">
                <table className="w-full">
                  <thead className="bg-white/5">
                    <tr>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">User</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Role</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Status</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">MFA</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Last Login</th>
                      <th className="py-4 px-6 text-left text-gray-300 font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user, index) => (
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
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            user.role === 'admin' ? 'bg-purple-500/20 text-purple-300' : 'bg-gray-500/20 text-gray-300'
                          }`}>
                            {user.role.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            user.status === 'active' ? 'bg-green-500/20 text-green-300' : 'bg-red-500/20 text-red-300'
                          }`}>
                            {user.status.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-4 px-6">
                          <span className={`text-lg ${user.mfaEnabled ? 'text-green-400' : 'text-red-400'}`}>
                            {user.mfaEnabled ? '✅' : '❌'}
                          </span>
                        </td>
                        <td className="py-4 px-6 text-gray-300">
                          {new Date(user.lastLogin).toLocaleString()}
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex space-x-2">
                            <button className="p-2 bg-blue-500/20 hover:bg-blue-500/30 rounded-lg text-blue-300 transition-all duration-200" title="Edit User">
                              ✏️
                            </button>
                            <button className="p-2 bg-yellow-500/20 hover:bg-yellow-500/30 rounded-lg text-yellow-300 transition-all duration-200" title="Suspend User">
                              ⏸️
                            </button>
                            <button className="p-2 bg-red-500/20 hover:bg-red-500/30 rounded-lg text-red-300 transition-all duration-200" title="Delete User">
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
          )}

          {/* Security Policies Tab */}
          {activeTab === "security" && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-4 flex items-center">
                    <span className="mr-2">🔐</span> Authentication Policies
                  </h3>
                  <div className="space-y-4">
                    {[
                      { label: "Enforce MFA for all users", enabled: true },
                      { label: "Require strong passwords", enabled: true },
                      { label: "Enable password expiration", enabled: false },
                      { label: "Lock account after failed attempts", enabled: true },
                      { label: "Enable SSO integration", enabled: false }
                    ].map((policy, index) => (
                      <div key={index} className="flex items-center justify-between">
                        <span className="text-gray-300">{policy.label}</span>
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input type="checkbox" className="sr-only peer" defaultChecked={policy.enabled} />
                          <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                        </label>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
                  <h3 className="text-xl font-semibold mb-4 flex items-center">
                    <span className="mr-2">⚙️</span> Session Management
                  </h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-gray-300 text-sm mb-2">Session Timeout (minutes)</label>
                      <input
                        type="number"
                        defaultValue="30"
                        className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                      />
                    </div>
                    <div>
                      <label className="block text-gray-300 text-sm mb-2">Maximum Concurrent Sessions</label>
                      <input
                        type="number"
                        defaultValue="3"
                        className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                      />
                    </div>
                    <div>
                      <label className="block text-gray-300 text-sm mb-2">Failed Login Attempts Limit</label>
                      <input
                        type="number"
                        defaultValue="5"
                        className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold mb-4 flex items-center">
                  <span className="mr-2">🛡️</span> Password Complexity Rules
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <label className="block text-gray-300 text-sm mb-2">Minimum Length</label>
                      <input
                        type="number"
                        defaultValue="12"
                        className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Require uppercase letters</span>
                      <input type="checkbox" defaultChecked className="w-5 h-5 text-purple-600 rounded" />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Require lowercase letters</span>
                      <input type="checkbox" defaultChecked className="w-5 h-5 text-purple-600 rounded" />
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Require numbers</span>
                      <input type="checkbox" defaultChecked className="w-5 h-5 text-purple-600 rounded" />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Require special characters</span>
                      <input type="checkbox" defaultChecked className="w-5 h-5 text-purple-600 rounded" />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-300">Prevent common passwords</span>
                      <input type="checkbox" defaultChecked className="w-5 h-5 text-purple-600 rounded" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Other tabs content would continue here... */}
          {activeTab === "audit" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-xl font-semibold">Audit Log Viewer</h3>
                <div className="flex space-x-2">
                  <button className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 font-semibold transition-all duration-300">
                    <span className="mr-2">📥</span> Export
                  </button>
                  <button className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg text-purple-300 font-semibold transition-all duration-300">
                    <span className="mr-2">🔍</span> Filter
                  </button>
                </div>
              </div>
              <p className="text-gray-400">Comprehensive audit logging system with filtering and export capabilities.</p>
            </div>
          )}

          {activeTab === "settings" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold mb-4">System Configuration</h3>
              <p className="text-gray-400">Configure system-wide settings, maintenance modes, and operational parameters.</p>
            </div>
          )}

          {activeTab === "integrations" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold mb-4">External Integrations</h3>
              <p className="text-gray-400">Manage connections to external services, APIs, and notification systems.</p>
            </div>
          )}

          {activeTab === "notifications" && (
            <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold mb-4">Notification Management</h3>
              <p className="text-gray-400">Configure alerts, notifications, and communication preferences.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
