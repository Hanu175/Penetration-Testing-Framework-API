# Internal Login System Documentation

## Penetration Testing Framework API

---

## 📋 Executive Summary

The **Penetration Testing Framework API** has a database-level user management system with a pre-configured admin account, **BUT the actual login functionality is NOT currently implemented in the frontend or backend API**.

The project has the infrastructure in place for authentication (users table, password fields), but:

- ❌ No login endpoint in the Flask backend
- ❌ No login HTML page in the frontend
- ❌ No authentication middleware protecting API endpoints
- ❌ All API endpoints are publicly accessible (no token/session validation)

This document explains:

1. **Current State**: How the system is set up now
2. **Database Infrastructure**: What data structures exist for login
3. **How Login WOULD Work**: If it were implemented
4. **Flow Diagrams**: Visual representation of the login process

---

## 🔍 Current Login Status

### ⚠️ Important Finding

The application currently operates **without any authentication mechanism**. All users can access all features without providing credentials.

**Default Admin Credentials** (defined in schema but not enforced):

```
Username: admin
Email:    admin@pentest.local
Password: admin123 (stored as plain text - NOT HASHED)
```

---

## 📊 Database Infrastructure for Login

### Users Table Structure

The database schema includes a `users` table designed to support authentication:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);
```

#### Table Fields Explained:

| Field           | Type                | Purpose                                              |
| --------------- | ------------------- | ---------------------------------------------------- |
| `id`            | INTEGER PRIMARY KEY | Unique identifier for each user                      |
| `username`      | TEXT UNIQUE         | Unique login identifier (e.g., "admin", "john_doe")  |
| `email`         | TEXT UNIQUE         | Unique email address for user communication          |
| `password_hash` | TEXT                | Stores hashed password (currently stores plain text) |
| `role`          | TEXT                | User role for authorization (e.g., "admin", "user")  |
| `created_at`    | TIMESTAMP           | Account creation timestamp                           |
| `last_login`    | TIMESTAMP           | Tracks last successful login time                    |

#### Current Data:

```sql
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@pentest.local', 'admin123', 'admin');
```

⚠️ **Security Issue**: Password stored as plain text, not hashed!

---

## 🔐 Project Relationships via Users

The user system connects to other tables through foreign keys:

```sql
-- Projects table references users
CREATE TABLE projects (
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Scans table references users who created them
CREATE TABLE scans (
    created_by INTEGER NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users (id)
);
```

**This enables**:

- Multi-user support (each user can have their own projects)
- Audit trails (track who created each scan)
- Access control (if implemented, users could only see their projects)

---

## 🚀 How Login WOULD Work (If Implemented)

### Step-by-Step Flow

#### **Phase 1: User Navigates to Login Page**

**Current Behavior:**

- User opens `http://localhost:5000/index.html`
- Goes directly to dashboard (NO login required)

**Expected Behavior (if implemented):**

1. User navigates to `http://localhost:5000/login.html`
2. Browser loads login page with username/password form

#### **Phase 2: User Clicks "Login" Button**

**What happens in Frontend (JavaScript)**:

```javascript
// File: frontend/js/login.js (DOES NOT EXIST - would need to be created)

document
  .getElementById("login-btn")
  .addEventListener("click", async function () {
    // Step 1: Get form values
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    // Step 2: Validate input
    if (!username || !password) {
      showError("Please enter username and password");
      return;
    }

    // Step 3: Send HTTP POST request to backend
    try {
      const response = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: username,
          password: password,
        }),
      });

      const data = await response.json();

      // Step 4: Handle response
      if (response.ok) {
        // Success - store token
        localStorage.setItem("auth_token", data.token);
        localStorage.setItem("user_id", data.user_id);

        // Redirect to dashboard
        window.location.href = "/index.html";
      } else {
        // Failure - show error
        showError(data.error);
      }
    } catch (error) {
      showError("Login failed: " + error.message);
    }
  });
```

#### **Phase 3: Backend Processes Login Request**

**Backend API Endpoint** (DOES NOT EXIST - would look like this):

```python
# File: backend/app.py (NOT IMPLEMENTED)

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """
    User login endpoint

    Request body:
    {
        "username": "admin",
        "password": "admin123"
    }
    """
    try:
        # Step 1: Get credentials from request
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Step 2: Validate input
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        # Step 3: Query database for user
        query = "SELECT * FROM users WHERE username = ?"
        user_results = db.execute_query(query, (username,))

        if not user_results:
            # User not found
            logger.warning(f"Login attempt with non-existent user: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        user = user_results[0]

        # Step 4: Verify password
        # In production, use: bcrypt.verify(password, user['password_hash'])
        if user['password_hash'] != password:  # INSECURE - plain text comparison
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        # Step 5: Update last_login timestamp
        query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?"
        db.execute_update(query, (user['id'],))

        # Step 6: Generate authentication token
        # Token would contain: user_id, username, role, expiration
        token = generate_jwt_token({
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.now() + timedelta(hours=24)
        })

        # Step 7: Return success response
        logger.info(f"Successful login: {username}")
        return jsonify({
            'success': True,
            'token': token,
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'email': user['email']
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
```

#### **Phase 4: Backend Database Query Execution**

**Query Flow in Database**:

```
1. Input Validation
   ├─ Check username not empty
   └─ Check password not empty

2. Database Query
   ├─ SQL: SELECT * FROM users WHERE username = ?
   └─ Database returns user record (if exists)

3. Record Structure (if found):
   {
       'id': 1,
       'username': 'admin',
       'email': 'admin@pentest.local',
       'password_hash': 'admin123',
       'role': 'admin',
       'created_at': '2026-04-27 10:00:00',
       'last_login': '2026-04-27 15:30:00'
   }

4. Password Verification
   ├─ Compare submitted password with password_hash
   ├─ If NOT match → Return 401 Unauthorized
   └─ If match → Continue to token generation

5. Update Timestamp
   ├─ SQL: UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = 1
   └─ Database records login time

6. Token Generation
   ├─ Create JWT token with user data
   ├─ Set expiration (24 hours)
   └─ Sign with SECRET_KEY
```

#### **Phase 5: Frontend Handles Response**

**Success Response (200 OK)**:

```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user_id": 1,
  "username": "admin",
  "role": "admin",
  "email": "admin@pentest.local"
}
```

**Frontend Actions**:

```javascript
// Store authentication data
localStorage.setItem("auth_token", response.token);
localStorage.setItem("user_id", response.user_id);
localStorage.setItem("username", response.username);
localStorage.setItem("role", response.role);

// Redirect to dashboard
window.location.href = "/index.html";

// Display: "Welcome, admin!"
```

**Failure Response (401 Unauthorized)**:

```json
{
  "error": "Invalid username or password"
}
```

**Frontend Actions**:

```javascript
// Show error message
showError("Invalid username or password");

// Keep on login page
// Clear any stored tokens
localStorage.removeItem("auth_token");
```

---

## 📈 Complete Login Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER LOGIN FLOW DIAGRAM                       │
└─────────────────────────────────────────────────────────────────┘

FRONTEND                          |  BACKEND                 | DATABASE
                                  |                          |
1. User enters credentials        |                          |
   (username, password)           |                          |
         ↓                        |                          |
2. Clicks "Login" button          |                          |
         ↓                        |                          |
3. JavaScript validates input    |                          |
         ↓                        |                          |
4. Sends POST request            |                          |
   /api/v1/auth/login            |                          |
         ├─────────────────────→ 5. Flask app receives    |
         |                        │  request               |
         |                        │       ↓                |
         |                        │ 6. Extract username    |
         |                        │    & password          |
         |                        │       ↓                |
         |                        │ 7. Query database      |
         |                        ├───────────────→ 8. SELECT * FROM users
         |                        |                │  WHERE username=?
         |                        │                │       ↓
         |                        │ 9. Database ←──┤ Return user record
         |                        │    receives user
         |                        │       ↓
         |                        │ 10. Compare passwords
         |                        │     (submitted vs stored)
         |                        │       ↓
         |                        │ 11. Passwords match?
         |                        │     ├─YES→ 12. Update last_login
         |                        ├──────────→ 13. UPDATE users
         |                        │    │       SET last_login = NOW
         |                        │    │              ↓
         |                        │    │      14. Database updates
         |                        │    │
         |                        │ 15. Generate JWT token
         |                        │     (user_id, role, exp)
         |                        │       ↓
         | 16. Return success   ←┤ 16. Return 200 OK
         | + token              |     + token + user data
         ←─────────────────────  │
         ↓                        |
17. Store token in              |
    localStorage                 |
    Store user_id               |
    Store role                  |
         ↓                        |
18. Redirect to dashboard       |
    (/index.html)              |
         ↓                        |
19. Load dashboard with token   |
    (attach to API requests)    |
```

---

## 🔑 Authentication Token (JWT)

When login succeeds, a JWT token is created. This token is used for subsequent API requests.

### Token Structure:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAiZXhwIjogMTcxNzc0MzIwMH0.signature
```

**Decoded Payload**:

```json
{
  "user_id": 1,
  "username": "admin",
  "role": "admin",
  "exp": 1717743200
}
```

### How Token is Used:

```javascript
// Subsequent API calls include token in header
const response = await fetch("/api/v1/scans", {
  method: "GET",
  headers: {
    Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  },
});
```

---

## 🛡️ Session Management

### Current Implementation: NONE (No Authentication)

### How Sessions WOULD Work (if implemented):

```
SESSION LIFECYCLE:

1. USER LOGS IN
   ├─ Submits credentials
   ├─ Server generates JWT token (expires in 24 hours)
   ├─ Token stored in browser localStorage
   └─ User redirected to dashboard

2. USER BROWSES APPLICATION
   ├─ Token included in every API request
   └─ Backend validates token before processing

3. TOKEN VALIDATION PROCESS
   ├─ Check if token is present
   ├─ Verify token signature (not tampered with)
   ├─ Check expiration date
   ├─ Extract user_id and role
   └─ Allow or deny request based on permissions

4. USER LOGS OUT
   ├─ JavaScript removes token from localStorage
   ├─ Redirect to login page
   └─ Subsequent requests fail (no token)

5. TOKEN EXPIRES
   ├─ User continues browsing after 24 hours
   ├─ API request includes expired token
   ├─ Backend rejects request with 401 error
   ├─ Frontend detects 401
   ├─ Clear localStorage
   └─ Redirect to login page (prompt "Session expired")
```

---

## 🔗 Related API Endpoints (If Implemented)

```
POST   /api/v1/auth/login
       Request:  { "username": "admin", "password": "admin123" }
       Response: { "token": "...", "user_id": 1, "role": "admin" }
       Status:   200 (success) | 401 (invalid credentials)

POST   /api/v1/auth/logout
       Request:  { "token": "..." }
       Response: { "message": "Logged out successfully" }
       Status:   200

POST   /api/v1/auth/refresh
       Request:  { "token": "..." }
       Response: { "token": "...", "expires_in": 86400 }
       Status:   200

GET    /api/v1/auth/me
       Headers:  Authorization: Bearer <token>
       Response: { "id": 1, "username": "admin", "email": "...", "role": "admin" }
       Status:   200 | 401 (invalid/expired token)

POST   /api/v1/auth/register
       Request:  { "username": "...", "email": "...", "password": "..." }
       Response: { "id": ..., "message": "User created" }
       Status:   201 | 400 (validation error)
```

---

## 📱 Frontend Components (To Be Created)

### 1. Login Page (`frontend/login.html`)

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Login - Penetration Testing Framework</title>
    <link rel="stylesheet" href="css/styles.css" />
  </head>
  <body>
    <div class="login-container">
      <h1>Login</h1>
      <form id="login-form">
        <input type="text" id="username" placeholder="Username" required />
        <input type="password" id="password" placeholder="Password" required />
        <button type="submit" id="login-btn">Login</button>
      </form>
      <div id="error-message" class="error"></div>
    </div>
    <script src="js/login.js"></script>
  </body>
</html>
```

### 2. Session Check (`frontend/js/session.js`)

```javascript
// Check if user is authenticated
function checkAuthentication() {
  const token = localStorage.getItem("auth_token");

  if (!token) {
    // No token - redirect to login
    window.location.href = "/login.html";
    return false;
  }

  // Token exists - user is logged in
  return true;
}

// Add to every protected page
document.addEventListener("DOMContentLoaded", checkAuthentication);
```

### 3. Authorization Check for API Calls

```javascript
// Include token in all API requests
async function authenticatedFetch(url, options = {}) {
  const token = localStorage.getItem("auth_token");

  const headers = {
    ...options.headers,
    Authorization: `Bearer ${token}`,
  };

  const response = await fetch(url, { ...options, headers });

  if (response.status === 401) {
    // Token invalid/expired - logout user
    localStorage.removeItem("auth_token");
    window.location.href = "/login.html";
  }

  return response;
}
```

---

## 🔒 Security Considerations

### Current Issues:

1. ❌ **No Authentication** - All endpoints publicly accessible
2. ❌ **No Authorization** - No role-based access control
3. ❌ **No Password Hashing** - Default password stored as plain text
4. ❌ **No HTTPS** - Running on HTTP (data in plain text)
5. ❌ **No CSRF Protection** - No token for form submissions

### If Implemented, Would Need:

1. ✅ **Password Hashing** - Use bcrypt or argon2
2. ✅ **HTTPS/SSL** - Encrypt all data in transit
3. ✅ **JWT Signing** - Use strong SECRET_KEY
4. ✅ **CORS Configuration** - Restrict origins
5. ✅ **Rate Limiting** - Prevent brute force attacks
6. ✅ **Password Requirements** - Min length, complexity
7. ✅ **Session Timeout** - Expire after inactivity
8. ✅ **Audit Logging** - Track all login attempts

---

## 📝 Current Code References

### Database Initialization

- File: [database/init_db.py](database/init_db.py)
  - Shows default admin credentials
  - Creates database with schema

### Database Schema

- File: [database/schema.sql](database/schema.sql)
  - Defines `users` table structure
  - Sets up foreign key relationships

### Configuration

- File: [backend/config.py](backend/config.py)
  - `SECRET_KEY` - Used for token signing (currently 'dev-secret-key-change-in-production')
  - `DATABASE_PATH` - Path to SQLite database

### Main Application

- File: [backend/app.py](backend/app.py)
  - Flask app configuration
  - API routes (no login endpoint currently)
  - CORS enabled for all origins

### Frontend

- Files: [frontend/index.html](frontend/index.html), [frontend/js/dashboard.js](frontend/js/dashboard.js)
  - Dashboard loads directly (no authentication check)

---

## 🎯 What Needs to Be Implemented

To activate the login system, the following would need to be created:

### Backend:

1. [ ] Login endpoint (`/api/v1/auth/login`)
2. [ ] Authentication middleware
3. [ ] JWT token generation/validation
4. [ ] Password hashing (bcrypt)
5. [ ] Authorization checks on API routes
6. [ ] Logout endpoint
7. [ ] Token refresh endpoint
8. [ ] User registration (optional)

### Frontend:

1. [ ] Login page (login.html)
2. [ ] Login JavaScript handler
3. [ ] Session validation on page load
4. [ ] Authentication state management
5. [ ] Logout button in navbar
6. [ ] Error handling for expired sessions
7. [ ] User profile display

### Database:

1. [ ] Fix password storage (hash instead of plain text)
2. [ ] Add admin credentials on first run

### Configuration:

1. [ ] Change SECRET_KEY to strong random value
2. [ ] Enable HTTPS in production
3. [ ] Configure CORS properly
4. [ ] Add password policy settings

---

## 📚 Summary

| Aspect                 | Current State        | Expected State (If Implemented) |
| ---------------------- | -------------------- | ------------------------------- |
| **Authentication**     | ❌ None              | ✅ JWT-based                    |
| **Login Page**         | ❌ Does not exist    | ✅ login.html                   |
| **Login Endpoint**     | ❌ Not implemented   | ✅ POST /api/v1/auth/login      |
| **Password Storage**   | ❌ Plain text        | ✅ Hashed (bcrypt)              |
| **Session Management** | ❌ No sessions       | ✅ Token-based (24h)            |
| **Authorization**      | ❌ No roles enforced | ✅ Admin/User roles             |
| **API Protection**     | ❌ All public        | ✅ Token-protected              |
| **HTTPS**              | ❌ HTTP only         | ✅ HTTPS required               |
| **User Table**         | ✅ Exists            | ✅ Used for auth                |
| **Audit Trail**        | ⚠️ Partial           | ✅ Full login tracking          |

---

## 🔗 Key Files to Review

```
Penetration-Testing-Framework-API/
├── database/
│   ├── schema.sql                 ← Users table definition
│   └── init_db.py                 ← Default credentials
├── backend/
│   ├── app.py                     ← Where login endpoint would go
│   ├── config.py                  ← SECRET_KEY, database config
│   └── utils/
│       └── database.py            ← Database operations
└── frontend/
    ├── index.html                 ← Currently loads directly
    ├── login.html                 ← MISSING - needs creation
    └── js/
        ├── dashboard.js           ← API calls (no auth yet)
        └── login.js               ← MISSING - needs creation
```

---

## 🎓 Conclusion

The **Penetration Testing Framework API** has the database infrastructure for user authentication in place, but **no actual login mechanism is currently implemented**. All API endpoints are publicly accessible without authentication.

To enable login:

- Frontend needs a login page and session management
- Backend needs authentication endpoints and middleware
- Database already has the user table ready
- Password hashing and security measures should be added

The documented flow above shows exactly how each component would interact when a user clicks the login button, from the frontend HTTP request through the database query to the token generation and storage.
