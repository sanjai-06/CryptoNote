import axios from "axios";

const API = axios.create({ baseURL: "http://localhost:3001/api" });

// Add token automatically if available
API.interceptors.request.use((req) => {
  const token = localStorage.getItem("token");
  if (token) {
    req.headers.Authorization = `Bearer ${token}`;
  }
  return req;
});

// Enforce 2FA: if backend requires 2FA, redirect user to profile security
API.interceptors.response.use(
  (res) => res,
  (error) => {
    const code = error?.response?.data?.code;
    if (code === "TWO_FACTOR_REQUIRED") {
      // Avoid infinite redirect loops from the profile page itself
      const current = window.location.pathname;
      if (current !== "/profile") {
        // Optional: flag so profile can auto-open the 2FA modal
        sessionStorage.setItem("force2FASetup", "1");
        window.location.assign("/profile");
      }
    }
    // If unauthorized, clear token and send to login
    if (error?.response?.status === 401) {
      try { localStorage.removeItem("token"); } catch {}
      const current = window.location.pathname;
      if (current !== "/login") {
        window.location.assign("/login");
      }
    }
    return Promise.reject(error);
  }
);

export default API;
