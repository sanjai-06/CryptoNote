import { useNavigate } from "react-router-dom";

export default function Navigation({ currentPage = "dashboard" }) {
  const navigate = useNavigate();

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: "🏠", path: "/dashboard" },
    { id: "profile", label: "Profile", icon: "👤", path: "/profile" },
    { id: "admin", label: "Admin", icon: "👑", path: "/admin" }
  ];

  return (
    <div className="flex flex-wrap gap-3 mb-6">
      {navItems.map(item => (
        <button
          key={item.id}
          onClick={() => navigate(item.path)}
          className={`px-4 py-2 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 ${
            currentPage === item.id
              ? "bg-gradient-to-r from-purple-600 to-blue-600 text-white"
              : "bg-white/10 hover:bg-white/20 text-gray-300"
          }`}
        >
          <span className="mr-2">{item.icon}</span>
          {item.label}
        </button>
      ))}
    </div>
  );
}
