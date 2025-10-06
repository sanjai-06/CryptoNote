import { useNavigate } from "react-router-dom";

export default function QuickNav() {
  const navigate = useNavigate();

  return (
    <div className="fixed top-4 right-4 z-50 flex gap-2">
      <button
        onClick={() => navigate("/profile")}
        className="px-4 py-2 bg-blue-500/80 hover:bg-blue-500 backdrop-blur-sm border border-blue-400/50 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg"
        title="Go to Profile"
      >
        <span className="mr-1">👤</span> Profile
      </button>
      <button
        onClick={() => navigate("/dashboard")}
        className="px-4 py-2 bg-purple-500/80 hover:bg-purple-500 backdrop-blur-sm border border-purple-400/50 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg"
        title="Go to Dashboard"
      >
        <span className="mr-1">🏠</span> Dashboard
      </button>
    </div>
  );
}
