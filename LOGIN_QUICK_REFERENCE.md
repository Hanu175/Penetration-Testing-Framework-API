# Login System - Quick Reference Guide

## 📍 Files Created

This documentation set includes:

### 1. **INTERNAL_LOGIN_DOCUMENTATION.md** (Main Document)

- Complete explanation of the login system
- Database schema and relationships
- Current state vs expected state
- All API endpoints (if implemented)
- Security considerations
- Files that need to be created/modified

### 2. **LOGIN_FLOWCHARTS_AND_DIAGRAMS.md** (Visual Reference)

- Sequence diagrams showing step-by-step flow
- Data flow through database
- State machines for authentication
- Database relationships
- Token lifecycle
- Error handling scenarios
- Code templates for JavaScript

---

## 🔴 CURRENT STATE: NO LOGIN IMPLEMENTED

```
✗ No login page exists
✗ No login endpoint in backend
✗ No authentication middleware
✗ All API endpoints are PUBLIC
✗ Any user can access everything
```

---

## 💾 Database Infrastructure (EXISTS)

```
✓ Users table created
✓ Admin account pre-configured
✓ Foreign keys set up
✓ Password field ready
✓ Audit fields (created_at, last_login)
```

---

## 🔑 Default Credentials (Currently Inactive)

```
Username:    admin
Email:       admin@pentest.local
Password:    admin123 (plain text - INSECURE)
Role:        admin
Database:    SQLite (database/pentest.db)
```

**⚠️ NOT ENFORCED - System has no authentication**

---

## 📊 Quick Feature Matrix

| Feature            | Current        | If Implemented             |
| ------------------ | -------------- | -------------------------- |
| Login Page         | ❌             | ✅ login.html              |
| Login Endpoint     | ❌             | ✅ POST /api/v1/auth/login |
| JWT Tokens         | ❌             | ✅ 24-hour expiration      |
| Session Management | ❌             | ✅ localStorage-based      |
| Authorization      | ❌             | ✅ Role-based (admin/user) |
| Password Hashing   | ❌             | ✅ bcrypt recommended      |
| Audit Trail        | ⚠️ Partial     | ✅ Full tracking           |
| User Profiles      | ✓ Schema Ready | ✅ Functional              |

---

## 🔄 Login Process at a Glance

### User Click "Login" Button

```
1. Frontend: Collect username & password from form
2. Frontend: Send POST to /api/v1/auth/login
3. Backend: Query users table for username
4. Backend: Verify password matches
5. Backend: Generate JWT token (expires in 24h)
6. Backend: Update last_login timestamp
7. Backend: Return token + user info (200 OK)
8. Frontend: Store token in localStorage
9. Frontend: Redirect to dashboard
10. Dashboard: Include token in all API requests
```

---

## 📁 Key Files Location

### Database

```
database/
├── pentest.db          ← SQLite database (created on init)
├── schema.sql          ← User table definition
└── init_db.py          ← Shows default credentials
```

### Backend

```
backend/
├── app.py              ← Where login endpoint would go
├── config.py           ← SECRET_KEY, database path
└── utils/
    └── database.py     ← Query execution
```

### Frontend (to be created)

```
frontend/
├── login.html          ← NEEDED: Login form page
├── index.html          ← Currently loads without auth check
└── js/
    ├── login.js        ← NEEDED: Login button handler
    ├── session.js      ← NEEDED: Auth token validation
    └── dashboard.js    ← API calls (no auth yet)
```

---

## 🚀 To Enable Login (Implementation Checklist)

### Backend (app.py)

- [ ] Create `/api/v1/auth/login` endpoint
- [ ] Create `/api/v1/auth/logout` endpoint
- [ ] Add authentication middleware
- [ ] Import JWT and bcrypt libraries
- [ ] Add token validation decorator
- [ ] Protect API endpoints with auth check

### Frontend

- [ ] Create login.html with form
- [ ] Create login.js with button handler
- [ ] Create session.js for token validation
- [ ] Modify index.html to check auth on load
- [ ] Add logout button to navbar
- [ ] Add 401 error handler (session expired)

### Database

- [ ] Update password storage (hash instead of plain text)
- [ ] Add password update function

### Configuration

- [ ] Change SECRET_KEY to random value
- [ ] Enable HTTPS in production
- [ ] Configure CORS restrictions
- [ ] Add password policy settings

---

## 🔐 What Happens When...

### User Logs In Successfully

```
1. Backend returns: {"token": "JWT...", "user_id": 1, "role": "admin"}
2. Frontend stores token in localStorage
3. Dashboard displays with "Welcome, admin!" message
4. All subsequent API calls include token in Authorization header
```

### User Provides Wrong Password

```
1. Backend query finds user
2. Password comparison fails
3. Backend returns: 401 Unauthorized
4. Frontend shows: "Invalid username or password"
5. User stays on login page
```

### Token Expires (After 24 Hours)

```
1. User makes API request with expired token
2. Backend checks token expiration
3. Backend returns: 401 Unauthorized
4. Frontend detects 401
5. Frontend removes token from localStorage
6. Frontend redirects to login page
7. Shows: "Session expired, please login again"
```

### Network Connection Fails

```
1. Frontend detects fetch error
2. Frontend shows: "Network error. Is the server running?"
3. User can retry
4. Password field is cleared
5. Login button is re-enabled
```

---

## 📈 Database Query When User Logs In

### Query Sent to SQLite

```sql
SELECT id, username, email, password_hash, role, created_at, last_login
FROM users
WHERE username = ?
LIMIT 1
```

### Result (If Found)

```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@pentest.local",
  "password_hash": "admin123",
  "role": "admin",
  "created_at": "2026-04-27 10:00:00",
  "last_login": "2026-04-27 15:45:30"
}
```

### Update Query (After Successful Login)

```sql
UPDATE users
SET last_login = CURRENT_TIMESTAMP
WHERE id = 1
```

---

## 🔑 JWT Token Breakdown

### Example Token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAiZXhwIjogMTcxNzgyOTMzMH0.
signature
```

### Decoded Payload

```json
{
    "user_id": 1,
    "username": "admin",
    "role": "admin",
    "exp": 1717829330  (2026-04-28 15:45:30)
}
```

### How It's Used

```javascript
// Store after login
localStorage.setItem("auth_token", "eyJ...");

// Use in API calls
fetch("/api/v1/scans", {
  headers: {
    Authorization: "Bearer eyJ...",
  },
});

// Check expiration
const decoded = jwt.decode(token);
if (decoded.exp < Date.now()) {
  // Token expired
}
```

---

## 🎯 Request/Response Examples

### Login Request (Success)

**HTTP Request**

```
POST /api/v1/auth/login HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
    "username": "admin",
    "password": "admin123"
}
```

**HTTP Response**

```
HTTP/1.1 200 OK
Content-Type: application/json

{
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user_id": 1,
    "username": "admin",
    "role": "admin",
    "email": "admin@pentest.local"
}
```

### Login Request (Failure - Wrong Password)

**HTTP Request**

```
POST /api/v1/auth/login HTTP/1.1
Host: localhost:5000
Content-Type: application/json

{
    "username": "admin",
    "password": "wrongpassword"
}
```

**HTTP Response**

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
    "error": "Invalid username or password"
}
```

### API Request With Token

**HTTP Request**

```
GET /api/v1/scans HTTP/1.1
Host: localhost:5000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

**HTTP Response**

```
HTTP/1.1 200 OK
Content-Type: application/json

{
    "scans": [
        {
            "id": 1,
            "scan_name": "Network Scan",
            "target": "192.168.1.1",
            "status": "completed"
        }
    ]
}
```

---

## 🛡️ Security Checklist (Before Production)

- [ ] Hash passwords using bcrypt or argon2
- [ ] Use HTTPS (not HTTP)
- [ ] Change SECRET_KEY to random strong value
- [ ] Use HTTP-only cookies instead of localStorage
- [ ] Enable CORS restrictions (specific origins only)
- [ ] Add rate limiting (prevent brute force)
- [ ] Add CSRF protection
- [ ] Implement password requirements
- [ ] Add login attempt logging
- [ ] Implement session timeout
- [ ] Use SameSite cookie attribute
- [ ] Add input validation/sanitization
- [ ] Implement 2FA (optional but recommended)

---

## 📞 Troubleshooting

### Problem: "401 Unauthorized" on API calls

**Solution:**

1. Check if token exists in localStorage
2. Check if token is expired
3. Verify token format in Authorization header ("Bearer <token>")
4. Check backend SECRET_KEY matches token signing key

### Problem: "Invalid username or password" keeps appearing

**Solution:**

1. Verify default credentials: admin / admin123
2. Check database file exists at database/pentest.db
3. Verify init_db.py was run to create schema
4. Check password hashing implementation (currently plain text)

### Problem: Token stored but still redirected to login

**Solution:**

1. Check if document.addEventListener('DOMContentLoaded') runs on page load
2. Verify localStorage actually contains token
3. Check browser console for errors
4. Verify fetch request includes Authorization header

### Problem: "Session expired" after just logging in

**Solution:**

1. Check token expiration time (should be 24 hours)
2. Verify server time matches client time
3. Check if SECRET_KEY changed (invalidates tokens)
4. Verify jwt.decode() is working correctly

---

## 🔗 Related Files in Project

```
Penetration Testing Framework Structure:

├── README.md                    ← Project overview
├── requirements.txt             ← Python dependencies
├── database/
│   ├── init_db.py              ← Database setup script
│   ├── schema.sql              ← User table + others
│   └── pentest.db              ← SQLite database file
├── backend/
│   ├── app.py                  ← Main API (where login goes)
│   ├── config.py               ← Configuration (SECRET_KEY)
│   ├── appcheck.py             ← Development script
│   ├── services/               ← Business logic
│   │   ├── scanner_service.py
│   │   ├── analyzer_service.py
│   │   ├── exploiter_service.py
│   │   └── ...
│   └── utils/
│       ├── database.py         ← Database operations
│       └── logger.py           ← Logging setup
├── frontend/
│   ├── index.html              ← Dashboard (needs auth check)
│   ├── new-scan.html           ← Create scan page
│   ├── scans.html              ← View all scans
│   ├── scan-details.html       ← Scan details
│   ├── login.html              ← NEEDS CREATION
│   ├── css/
│   │   └── styles.css          ← Styling
│   └── js/
│       ├── dashboard.js        ← Dashboard logic
│       ├── new-scan.js         ← Scan creation
│       ├── scans.js            ← Scans list
│       ├── scan-details.js     ← Scan details
│       ├── login.js            ← NEEDS CREATION
│       └── session.js          ← NEEDS CREATION
└── logs/                        ← Application logs
```

---

## 📚 Additional Resources

### Files to Read First

1. **INTERNAL_LOGIN_DOCUMENTATION.md** - Start here for comprehensive overview
2. **LOGIN_FLOWCHARTS_AND_DIAGRAMS.md** - Visual representation of all flows
3. **database/schema.sql** - Users table definition
4. **backend/config.py** - Configuration values

### Key Code Files

- **database/init_db.py** - Shows password initialization
- **backend/app.py** - Where API endpoints are defined
- **backend/utils/database.py** - How queries are executed
- **frontend/js/dashboard.js** - Example of API calls (without auth)

### To Test If Implemented

```bash
# Start backend
cd backend
python app.py

# Test login endpoint
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Test with token
curl http://localhost:5000/api/v1/scans \
  -H "Authorization: Bearer <token>"
```

---

## ✅ Quick Facts

- **Project**: Penetration Testing Framework API
- **Database**: SQLite (database/pentest.db)
- **Backend**: Flask (Python)
- **Frontend**: Vanilla JavaScript + HTML/CSS
- **Authentication**: Would be JWT-based (currently none)
- **Session Duration**: Would be 24 hours (currently N/A)
- **Default User**: admin / admin123 (defined but not enforced)
- **Status**: Login infrastructure exists, implementation missing

---

## 📝 Document Version

- Created: April 27, 2026
- Purpose: Document internal login process flow
- Scope: Complete explanation without code changes
- Status: Documentation only (no implementation)

---

## Questions?

Refer to:

1. **INTERNAL_LOGIN_DOCUMENTATION.md** - For comprehensive details
2. **LOGIN_FLOWCHARTS_AND_DIAGRAMS.md** - For visual representations
3. **Database schema** - For table structure
4. **Code files** - For current implementation

The documentation explains everything that WOULD happen if the login system were fully implemented, with detailed breakdowns of each step in the process.
