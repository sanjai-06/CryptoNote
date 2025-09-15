# CryptoNote Copilot Instructions

## Project Overview
- **CryptoNote** is a full-stack password manager with strong security and a modern UI.
- **Frontend**: React (Vite, Tailwind CSS) in `client/vite-project/`.
- **Backend**: Node.js/Express in `server/` with MongoDB (Atlas) and email notifications.
- **Encryption**: Passwords are encrypted using AES-256-CBC on the backend. Client-side encryption is planned (see `README.md`).

## Key Architectural Patterns
- **Frontend** communicates with backend via REST API (see `server/routes/`).
- **Password CRUD**: All password operations are protected by authentication middleware (`server/middleware/auth.js`).
- **Category Management**: Categories are managed in the dashboard and can be created/edited/deleted (see `CategoryManager.jsx`).
- **Email Notifications**: On password/master password changes, users receive styled HTML emails (`server/services/emailService.js`).
- **Protected Routes**: Frontend uses `ProtectedRoute.jsx` to guard sensitive pages.

## Developer Workflows
- **Frontend**:
  - Install: `npm install` in `client/vite-project/`
  - Dev server: `npm run dev` (default: http://localhost:5173)
  - Build: `npm run build`
- **Backend**:
  - Install: `npm install` in `server/`
  - Start: `node server.js` (default: http://localhost:5000)
  - Uses `.env` for secrets (see `ENCRYPTION_KEY`, `EMAIL_FROM`, etc.)
- **Testing**: No formal test suite; manual testing via UI and API is standard.

## Project-Specific Conventions
- **Password encryption**: Always use the `encrypt`/`decrypt` helpers in `server/routes/passwords.js`.
- **Error handling**: API errors are returned as JSON with `message` or `errors` fields; frontend displays these in forms.
- **UI**: Consistent use of Tailwind for glassmorphism, gradients, and animated backgrounds.
- **Icons/Colors**: Categories and UI elements use emoji and color pickers for personalization.
- **Notifications**: All sensitive changes (password/master password) trigger email alerts.

## Integration Points
- **API base URL**: Set in `client/vite-project/src/api/axios.js`.
- **Email**: Uses Nodemailer; see `emailService.js` for templates and environment variables.
- **Environment**: Both client and server expect `.env` files for config.

## Examples
- To add a new password field, update both the backend model (`server/models/Password.js`) and the dashboard UI (`Dashboard.jsx`).
- To add a new notification type, extend `emailService.js` and call from the relevant route.

---

**For AI agents:**
- Always follow the encryption and notification patterns.
- Reference the README files for setup and tech stack details.
- When in doubt, check for conventions in existing components and routes.
