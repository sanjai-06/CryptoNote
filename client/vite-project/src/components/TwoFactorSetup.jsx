import { useState } from "react";
import API from "../api/axios";
import TwoFactorAuth from "./TwoFactorAuth";

export default function TwoFactorSetup({ user, onUpdate }) {
  const [showSetup, setShowSetup] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleEnable2FA = () => {
    setShowSetup(true);
  };

  const handleDisable2FA = async () => {
    const code = window.prompt("Enter your current 6-digit authenticator code to disable 2FA:");
    if (!code) return;

    setLoading(true);
    setError("");

    try {
      await API.post("/auth/disable-2fa", { code });
      onUpdate({ ...user, twoFactorEnabled: false });
    } catch (err) {
      setError(err.response?.data?.message || "Failed to disable 2FA");
    } finally {
      setLoading(false);
    }
  };

  const handle2FASuccess = () => {
    setShowSetup(false);
    onUpdate({ ...user, twoFactorEnabled: true });
  };

  const handleResendEmail = async () => {
    setLoading(true);
    setError("");
    setSuccess("");

    try {
      await API.post("/auth/send-2fa-email");
      setSuccess("2FA setup email sent successfully! Check your inbox.");
    } catch (err) {
      setError(err.response?.data?.message || "Failed to send email");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white/5 backdrop-blur-lg border border-white/10 rounded-xl p-6">
      <h3 className="text-xl font-semibold mb-4 flex items-center">
        <span className="mr-2">🔐</span>
        Two-Factor Authentication
      </h3>

      {error && (
        <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-3 rounded-lg mb-4 text-sm">
          <span className="text-red-300">⚠️</span> {error}
        </div>
      )}

      {success && (
        <div className="bg-green-500/20 border border-green-500/30 text-green-200 p-3 rounded-lg mb-4 text-sm">
          <span className="text-green-300">✅</span> {success}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-300 mb-2">
            {user?.twoFactorEnabled ? "2FA is enabled" : "2FA is disabled"}
          </p>
          <p className="text-gray-400 text-sm">
            {user?.twoFactorEnabled 
              ? "Your account is protected with two-factor authentication" 
              : "Add an extra layer of security to your account"
            }
          </p>
        </div>
        <div className="flex space-x-3">
          {user?.twoFactorEnabled && (
            <button
              onClick={handleResendEmail}
              disabled={loading}
              className={`px-4 py-3 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 text-blue-300 ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <span className="mr-2">📧</span>
              {loading ? "Sending..." : "Email Setup Guide"}
            </button>
          )}
          
          <button
            onClick={user?.twoFactorEnabled ? handleDisable2FA : handleEnable2FA}
            disabled={loading}
            className={`px-6 py-3 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 ${
              user?.twoFactorEnabled
                ? "bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 text-red-300"
                : "bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 text-green-300"
            } ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            <span className="mr-2">{user?.twoFactorEnabled ? "🔓" : "🔒"}</span>
            {loading ? "Processing..." : user?.twoFactorEnabled ? "Disable 2FA" : "Enable 2FA"}
          </button>
        </div>
      </div>

      {/* 2FA Setup Modal */}
      <TwoFactorAuth
        isOpen={showSetup}
        onClose={() => setShowSetup(false)}
        onSuccess={handle2FASuccess}
        email={user?.email}
        tempToken=""
      />
    </div>
  );
}
