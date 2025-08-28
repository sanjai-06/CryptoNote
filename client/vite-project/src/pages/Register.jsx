import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import API from "../api/axios";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";

export default function Register() {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [passwordValidation, setPasswordValidation] = useState(null);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    // Check if password is strong enough
    if (passwordValidation && !passwordValidation.isValidMasterPassword) {
      setError("Please use a stronger master password. It must be 'Strong' or 'Very Strong' to protect your vault.");
      setLoading(false);
      return;
    }

    try {
      const res = await API.post("/auth/register", form);
      alert(res.data.message || "Registered successfully!");
      navigate("/login");
    } catch (err) {
      console.error("Registration error:", err);
      console.error("Error response:", err.response);

      // Handle password strength errors from server
      if (err.response?.data?.errors) {
        setError(`Password requirements not met: ${err.response.data.errors.join(', ')}`);
      } else {
        setError(err.response?.data?.message || err.message || "Registration failed");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-900 text-white flex items-center justify-center relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-green-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
        <div className="absolute bottom-1/4 left-1/4 w-96 h-96 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* Glass morphism card */}
        <div className="bg-white/10 backdrop-blur-lg border border-white/20 shadow-2xl rounded-3xl p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-green-500 to-blue-600 rounded-full mb-4 shadow-lg">
              <span className="text-2xl">🚀</span>
            </div>
            <h2 className="text-3xl font-bold bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text text-transparent">
              Join CryptoNote
            </h2>
            <p className="text-gray-300 mt-2">Create your secure digital vault</p>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-4 rounded-xl mb-6 text-center backdrop-blur-sm">
              <span className="text-red-300">⚠️</span> {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-4">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Choose a username"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-300"
                  required
                />
                <div className="absolute inset-y-0 right-0 flex items-center pr-4">
                  <span className="text-gray-400">👤</span>
                </div>
              </div>

              <div className="relative">
                <input
                  type="email"
                  placeholder="Email address"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-300"
                  required
                />
                <div className="absolute inset-y-0 right-0 flex items-center pr-4">
                  <span className="text-gray-400">📧</span>
                </div>
              </div>

              <div className="relative">
                <input
                  type="password"
                  placeholder="Create a strong master password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className="w-full p-4 bg-white/5 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-300"
                  required
                />
                <div className="absolute inset-y-0 right-0 flex items-center pr-4">
                  <span className="text-gray-400">🔒</span>
                </div>

                {/* Password Strength Meter */}
                <PasswordStrengthMeter
                  password={form.password}
                  onValidation={setPasswordValidation}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="group relative w-full py-4 bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 rounded-xl text-white font-bold text-lg transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100 shadow-lg hover:shadow-green-500/25"
            >
              <span className="relative z-10">
                {loading ? (
                  <span className="flex items-center justify-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Creating account...
                  </span>
                ) : (
                  "Create Account"
                )}
              </span>
              <div className="absolute inset-0 bg-gradient-to-r from-green-400 to-blue-400 rounded-xl blur opacity-0 group-hover:opacity-20 transition-opacity duration-300"></div>
            </button>
          </form>

          <div className="mt-8 text-center">
            <p className="text-gray-400">
              Already have an account?{" "}
              <Link
                to="/login"
                className="text-green-400 hover:text-green-300 font-semibold transition-colors duration-300 hover:underline"
              >
                Sign in here
              </Link>
            </p>
          </div>

          <div className="mt-6 text-center">
            <Link
              to="/"
              className="text-gray-500 hover:text-gray-300 text-sm transition-colors duration-300"
            >
              ← Back to home
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
