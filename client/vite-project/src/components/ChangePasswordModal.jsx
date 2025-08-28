import { useState } from "react";
import API from "../api/axios";
import PasswordStrengthMeter from "./PasswordStrengthMeter";

export default function ChangePasswordModal({ isOpen, onClose, onSuccess }) {
  const [form, setForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: ""
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [passwordValidation, setPasswordValidation] = useState(null);
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    // Validate passwords match
    if (form.newPassword !== form.confirmPassword) {
      setError("New passwords do not match");
      setLoading(false);
      return;
    }

    // Check if password is strong enough
    if (passwordValidation && !passwordValidation.isValidMasterPassword) {
      setError("Please use a stronger master password. It must be 'Strong' or 'Very Strong' to protect your vault.");
      setLoading(false);
      return;
    }

    try {
      const res = await API.put("/auth/change-password", {
        currentPassword: form.currentPassword,
        newPassword: form.newPassword
      });
      
      alert("Master password changed successfully! You will receive an email notification.");
      setForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
      onSuccess?.();
      onClose();
    } catch (err) {
      console.error("Password change error:", err);
      
      if (err.response?.data?.errors) {
        setError(`Password requirements not met: ${err.response.data.errors.join(', ')}`);
      } else {
        setError(err.response?.data?.message || "Failed to change password");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
    setError("");
    setPasswordValidation(null);
    setShowPasswords({ current: false, new: false, confirm: false });
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900/95 backdrop-blur-lg border border-white/20 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold text-white flex items-center">
            <span className="mr-2">🔐</span> Change Master Password
          </h3>
          <button
            onClick={handleClose}
            className="p-1 text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-4 rounded-xl mb-6 text-center backdrop-blur-sm">
            <span className="text-red-300">⚠️</span> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Current Password */}
          <div className="relative">
            <input
              type={showPasswords.current ? "text" : "password"}
              placeholder="Current master password"
              value={form.currentPassword}
              onChange={(e) => setForm({ ...form, currentPassword: e.target.value })}
              className="w-full p-4 pr-20 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300"
              required
            />
            <div className="absolute inset-y-0 right-0 flex items-center pr-4 space-x-2">
              <button
                type="button"
                onClick={() => setShowPasswords({ ...showPasswords, current: !showPasswords.current })}
                className="text-gray-400 hover:text-white transition-colors p-1"
                title={showPasswords.current ? "Hide password" : "Show password"}
              >
                {showPasswords.current ? "🙈" : "👁️"}
              </button>
              <span className="text-gray-400">🔒</span>
            </div>
          </div>

          {/* New Password */}
          <div className="relative">
            <input
              type={showPasswords.new ? "text" : "password"}
              placeholder="New master password"
              value={form.newPassword}
              onChange={(e) => setForm({ ...form, newPassword: e.target.value })}
              className="w-full p-4 pr-20 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300"
              required
            />
            <div className="absolute inset-y-0 right-0 flex items-center pr-4 space-x-2">
              <button
                type="button"
                onClick={() => setShowPasswords({ ...showPasswords, new: !showPasswords.new })}
                className="text-gray-400 hover:text-white transition-colors p-1"
                title={showPasswords.new ? "Hide password" : "Show password"}
              >
                {showPasswords.new ? "🙈" : "👁️"}
              </button>
              <span className="text-gray-400">🔑</span>
            </div>

            {/* Password Strength Meter */}
            <PasswordStrengthMeter
              password={form.newPassword}
              onValidation={setPasswordValidation}
            />
          </div>

          {/* Confirm Password */}
          <div className="relative">
            <input
              type={showPasswords.confirm ? "text" : "password"}
              placeholder="Confirm new password"
              value={form.confirmPassword}
              onChange={(e) => setForm({ ...form, confirmPassword: e.target.value })}
              className="w-full p-4 pr-20 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all duration-300"
              required
            />
            <div className="absolute inset-y-0 right-0 flex items-center pr-4 space-x-2">
              <button
                type="button"
                onClick={() => setShowPasswords({ ...showPasswords, confirm: !showPasswords.confirm })}
                className="text-gray-400 hover:text-white transition-colors p-1"
                title={showPasswords.confirm ? "Hide password" : "Show password"}
              >
                {showPasswords.confirm ? "🙈" : "👁️"}
              </button>
              <span className="text-gray-400">✓</span>
            </div>
            
            {/* Password Match Indicator */}
            {form.confirmPassword && (
              <div className={`mt-2 text-sm flex items-center ${
                form.newPassword === form.confirmPassword ? 'text-green-400' : 'text-red-400'
              }`}>
                <span className="mr-2">
                  {form.newPassword === form.confirmPassword ? '✓' : '✗'}
                </span>
                {form.newPassword === form.confirmPassword ? 'Passwords match' : 'Passwords do not match'}
              </div>
            )}
          </div>

          {/* Security Notice */}
          <div className="bg-blue-500/20 border border-blue-500/30 rounded-xl p-4">
            <div className="text-blue-300 text-sm font-medium flex items-center mb-2">
              <span className="mr-2">🛡️</span>
              Security Notice
            </div>
            <ul className="text-blue-200 text-xs space-y-1">
              <li>• You will receive an email notification after changing your password</li>
              <li>• Your master password protects all your stored passwords</li>
              <li>• Use a unique, strong password that you don't use anywhere else</li>
              <li>• Consider using a passphrase with random words</li>
            </ul>
          </div>

          {/* Buttons */}
          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={handleClose}
              className="flex-1 py-3 bg-gray-500/20 hover:bg-gray-500/30 border border-gray-500/30 rounded-xl text-gray-300 font-semibold transition-all duration-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !passwordValidation?.isValidMasterPassword || form.newPassword !== form.confirmPassword}
              className="flex-1 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 rounded-xl text-white font-semibold transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Changing...
                </span>
              ) : (
                <span className="flex items-center justify-center">
                  <span className="mr-2">🔐</span>
                  Change Password
                </span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
