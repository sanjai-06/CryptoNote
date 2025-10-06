import { useState, useEffect } from "react";

export default function SecurityDashboard() {
  const [securityMetrics, setSecurityMetrics] = useState({
    threatLevel: "medium",
    activeThreats: 3,
    blockedAttempts: 127,
    suspiciousActivities: 8,
    lastScan: "2024-10-06T08:30:00Z"
  });

  const [recentThreats, setRecentThreats] = useState([
    { id: 1, type: "Brute Force", source: "192.168.1.100", severity: "high", timestamp: "2024-10-06T09:15:00Z", status: "blocked" },
    { id: 2, type: "SQL Injection", source: "203.45.67.89", severity: "critical", timestamp: "2024-10-06T08:45:00Z", status: "blocked" },
    { id: 3, type: "Suspicious Login", source: "10.0.0.50", severity: "medium", timestamp: "2024-10-06T08:30:00Z", status: "investigating" }
  ]);

  const getThreatLevelColor = (level) => {
    switch (level) {
      case "low": return "text-green-400 bg-green-500/20";
      case "medium": return "text-yellow-400 bg-yellow-500/20";
      case "high": return "text-red-400 bg-red-500/20";
      case "critical": return "text-red-400 bg-red-500/30 animate-pulse";
      default: return "text-gray-400 bg-gray-500/20";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "critical": return "🚨";
      case "high": return "⚠️";
      case "medium": return "🟡";
      case "low": return "🟢";
      default: return "ℹ️";
    }
  };

  return (
    <div className="space-y-6">
      {/* Security Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">🛡️</span>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getThreatLevelColor(securityMetrics.threatLevel)}`}>
              {securityMetrics.threatLevel.toUpperCase()}
            </span>
          </div>
          <h3 className="text-gray-400 text-sm mb-2">Threat Level</h3>
          <p className="text-2xl font-bold text-white">{securityMetrics.threatLevel}</p>
        </div>

        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">⚡</span>
            </div>
          </div>
          <h3 className="text-gray-400 text-sm mb-2">Active Threats</h3>
          <p className="text-3xl font-bold text-orange-400">{securityMetrics.activeThreats}</p>
        </div>

        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">🚫</span>
            </div>
          </div>
          <h3 className="text-gray-400 text-sm mb-2">Blocked Attempts</h3>
          <p className="text-3xl font-bold text-green-400">{securityMetrics.blockedAttempts}</p>
        </div>

        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
              <span className="text-2xl">🔍</span>
            </div>
          </div>
          <h3 className="text-gray-400 text-sm mb-2">Suspicious Activities</h3>
          <p className="text-3xl font-bold text-purple-400">{securityMetrics.suspiciousActivities}</p>
        </div>
      </div>

      {/* Real-time Threat Monitor */}
      <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold flex items-center">
            <span className="mr-2">🔴</span> Real-time Threat Monitor
          </h3>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-green-400 text-sm">Live</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-white/5">
              <tr>
                <th className="py-3 px-4 text-left text-gray-300 font-semibold">Threat Type</th>
                <th className="py-3 px-4 text-left text-gray-300 font-semibold">Source IP</th>
                <th className="py-3 px-4 text-left text-gray-300 font-semibold">Severity</th>
                <th className="py-3 px-4 text-left text-gray-300 font-semibold">Time</th>
                <th className="py-3 px-4 text-left text-gray-300 font-semibold">Status</th>
                <th className="py-3 px-4 text-left text-gray-300 font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentThreats.map((threat, index) => (
                <tr key={threat.id} className={`border-b border-white/10 hover:bg-white/5 transition-colors ${index % 2 === 0 ? 'bg-white/2' : ''}`}>
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{getSeverityIcon(threat.severity)}</span>
                      <span className="text-white font-semibold">{threat.type}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="font-mono text-gray-300">{threat.source}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${getThreatLevelColor(threat.severity)}`}>
                      {threat.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-gray-300">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                      threat.status === 'blocked' ? 'bg-green-500/20 text-green-300' : 
                      threat.status === 'investigating' ? 'bg-yellow-500/20 text-yellow-300' : 
                      'bg-red-500/20 text-red-300'
                    }`}>
                      {threat.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex space-x-2">
                      <button className="p-1 bg-blue-500/20 hover:bg-blue-500/30 rounded text-blue-300 transition-all duration-200" title="View Details">
                        👁️
                      </button>
                      <button className="p-1 bg-red-500/20 hover:bg-red-500/30 rounded text-red-300 transition-all duration-200" title="Block IP">
                        🚫
                      </button>
                      <button className="p-1 bg-green-500/20 hover:bg-green-500/30 rounded text-green-300 transition-all duration-200" title="Whitelist">
                        ✅
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
          <h3 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">⚡</span> Quick Actions
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <button className="p-4 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg text-red-300 font-semibold transition-all duration-300 text-center">
              <div className="text-2xl mb-2">🚨</div>
              <div>Emergency Lockdown</div>
            </button>
            <button className="p-4 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 font-semibold transition-all duration-300 text-center">
              <div className="text-2xl mb-2">🔍</div>
              <div>Security Scan</div>
            </button>
            <button className="p-4 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg text-green-300 font-semibold transition-all duration-300 text-center">
              <div className="text-2xl mb-2">🛡️</div>
              <div>Enable Shields</div>
            </button>
            <button className="p-4 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg text-purple-300 font-semibold transition-all duration-300 text-center">
              <div className="text-2xl mb-2">📊</div>
              <div>Generate Report</div>
            </button>
          </div>
        </div>

        <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
          <h3 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">📈</span> Security Trends
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-300">Attack Attempts (24h)</span>
                <span className="text-red-400 font-semibold">↗ +23%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div className="bg-red-500 h-2 rounded-full" style={{ width: '75%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-300">Successful Blocks</span>
                <span className="text-green-400 font-semibold">↗ +45%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '90%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-300">False Positives</span>
                <span className="text-blue-400 font-semibold">↘ -12%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div className="bg-blue-500 h-2 rounded-full" style={{ width: '15%' }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
