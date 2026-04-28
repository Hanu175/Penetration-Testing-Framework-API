# Login Process - Visual Diagrams and Detailed Flowcharts

## 🔄 Complete Login Sequence Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOGIN SEQUENCE DIAGRAM                              │
│                    (Showing all interactions step-by-step)                   │
└─────────────────────────────────────────────────────────────────────────────┘

USER INTERFACE              JAVASCRIPT ENGINE           BACKEND SERVER         DATABASE
        |                         |                            |                   |
        |  1. User enters         |                            |                   |
        |  username & password    |                            |                   |
        |──────────────────┐      |                            |                   |
        |                 └─────→ |                            |                   |
        |                         |                            |                   |
        |  2. User clicks         |                            |                   |
        |  "Login" button         |                            |                   |
        |──────────────────────┐  |                            |                   |
        |                     └─→ |                            |                   |
        |                         | 3. Validate form data      |                   |
        |                         | (not empty, format check)  |                   |
        |                         |                            |                   |
        |                         | 4. Make HTTP POST request  |                   |
        |                         |  /api/v1/auth/login        |                   |
        |                         |────────────────────────────→|                   |
        |                         |                            | 5. Receive       |
        |                         |                            |    credentials   |
        |                         |                            |                   |
        |                         |                            | 6. Extract:      |
        |                         |                            |    username,     |
        |                         |                            |    password      |
        |                         |                            |                   |
        |                         |                            | 7. Query user    |
        |                         |                            |────────────────→ |
        |                         |                            |  SELECT *       |
        |                         |                            |  FROM users     |
        |                         |                            |  WHERE           |
        |                         |                            |  username = ?   |
        |                         |                            |                   |
        |                         |                            | ← 8. Return user |
        |                         |                            |    record (if    |
        |                         |                            |    exists)       |
        |                         |                            |                   |
        |                         |                            | 9. Check if user|
        |                         |                            |    was found     |
        |                         |                            |                   |
        |                         |  ┌─ NOT FOUND ──────────┐  |                   |
        |                         |  │                      │  |                   |
        |                         | 10. Password match?    │  |                   |
        |                         |  │   Compare submitted │  |                   |
        |                         |  │   vs stored password │  |                   |
        |                         |  │                      │  |                   |
        |  FAILURE RESPONSE       │  └─ NO MATCH ────────┐ │  |                   |
        |  (401 Error)            │                     │ │  |                   |
        |← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │  11. Return 401     │ │  |                   |
        |                         |  Unauthorized ←─────│─┤  |                   |
        |                         |                     │ │  |                   |
        | 12. Show error          │                     │ │  |                   |
        | message to user         │                     └─→  |                   |
        |                         │                          |                   |
        |   CONTINUE              │                          |                   |
        |   (Passwords match)     │                          |                   |
        |                         │                      YES │                   |
        |                         │                      ────→ 13. Update       |
        |                         │                          |    last_login    |
        |                         │                          |────────────────→ |
        |                         │                          |  UPDATE users   |
        |                         │                          |  SET last_login |
        |                         │                          |  = CURRENT_TIME |
        |                         │                          | ← 14. Confirm   |
        |                         │                          |                   |
        |                         │                      YES │                   |
        |                         │                      ────→ 15. Generate JWT|
        |                         │                          |    token with:  |
        |                         │                          |    - user_id: 1 |
        |                         │                          |    - username   |
        |                         │                          |    - role       |
        |                         │                          |    - exp: +24h  |
        |                         │                          |                   |
        |  SUCCESS RESPONSE       │                          |                   |
        |  (200 OK + token)       │                          |                   |
        |← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ← ─ ─ ─ ─ ─ ─ ─ ─ ─|
        |                         │ 16. Parse JSON response │                   |
        |                         |     Extract token       │                   |
        |                         │     Extract user info   │                   |
        |                         │                         │                   |
        | 17. Store in browser    │                         │                   |
        | localStorage:           │                         │                   |
        | - auth_token            │                         │                   |
        | - user_id               │                         │                   |
        | - username              │                         │                   |
        | - role                  │                         │                   |
        |──────────────────────┐  │                         │                   |
        |                     └─→ |                         │                   |
        |                         | 18. Redirect to        │                   |
        |                         | dashboard page         │                   |
        | 19. Display:            |                         │                   |
        | "Welcome, admin!"       │                         │                   |
        | Navbar with logout      │                         │                   |
        |──────────────────────┐  │                         │                   |
        |                     └─→ |                         │                   |
        |                         | 20. On future requests:|                   |
        |                         | Include token in:      │                   |
        |                         | Authorization header   │                   |
        |                         |                         │                   |
        |                         | Headers:               │                   |
        |                         | Authorization:Bearer<token>               │
        |                         |────────────────────────→|                   |
        |                         |                         |                   |
        |                         |                         | Validate token  |
        |                         |                         | before processing
        |                         |                         | request          |
        |                         |                         │                   |

```

---

## 🗂️ Data Flow Through Database

### When User Submits Login Form

```
USER SUBMISSION
    ↓
    └─→ {
        "username": "admin",
        "password": "admin123"
    }
    ↓
BACKEND RECEIVES & VALIDATES
    ├─ Check username not empty: ✓
    ├─ Check password not empty: ✓
    └─ Format looks valid: ✓
    ↓
DATABASE QUERY EXECUTED
    ├─ SQL Query:
    │  SELECT id, username, email, password_hash, role, created_at, last_login
    │  FROM users
    │  WHERE username = "admin"
    │
    ├─ Query Execution Plan:
    │  1. Scan users table
    │  2. Find row where username column = "admin"
    │  3. Return entire row
    │
    └─ Result:
       {
           'id': 1,
           'username': 'admin',
           'email': 'admin@pentest.local',
           'password_hash': 'admin123',
           'role': 'admin',
           'created_at': '2026-04-27 10:00:00',
           'last_login': '2026-04-27 15:30:00'
       }
    ↓
PASSWORD VERIFICATION
    ├─ Submitted password: "admin123"
    ├─ Stored password: "admin123"
    ├─ Comparison: admin123 === admin123
    └─ Result: MATCH ✓
    ↓
UPDATE LAST LOGIN
    ├─ SQL Query:
    │  UPDATE users
    │  SET last_login = CURRENT_TIMESTAMP
    │  WHERE id = 1
    │
    └─ Database updated: last_login = 2026-04-27 15:45:30
    ↓
TOKEN GENERATION
    ├─ Create payload:
    │  {
    │      "user_id": 1,
    │      "username": "admin",
    │      "role": "admin",
    │      "exp": 1717829330
    │  }
    │
    ├─ Encode with SECRET_KEY
    ├─ Add signature
    │
    └─ Result: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAiZXhwIjogMTcxNzgyOTMzMH0.signature
    ↓
RESPONSE TO BROWSER
    └─ {
        "success": true,
        "token": "eyJ...",
        "user_id": 1,
        "username": "admin",
        "role": "admin",
        "email": "admin@pentest.local"
    }
```

---

## 🎯 User Authentication State Flow

```
┌──────────────────────────────────────────────────────────────┐
│            USER AUTHENTICATION STATE MACHINE                  │
└──────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │    NOT LOGGED IN │
                    │  (No token)      │
                    └────────┬────────┘
                             │
                             │ 1. User opens login page
                             │
                    ┌────────▼─────────┐
                    │  LOGIN PAGE      │
                    │  Displayed       │
                    └────────┬─────────┘
                             │
                             │ 2. Enter credentials & submit
                             │
                    ┌────────▼─────────────────────┐
                    │  AUTHENTICATING              │
                    │  - Sending to backend        │
                    │  - Verifying credentials     │
                    │  - Generating token          │
                    └────────┬─────────┬──────────┘
                             │         │
                    ┌────────┘         └─────────┐
                    │                            │
            INVALID CREDENTIALS       VALID CREDENTIALS
                    │                            │
        ┌───────────▼────────────┐   ┌──────────▼──────────┐
        │  LOGIN FAILED          │   │  LOGIN SUCCESSFUL   │
        │  - Show error message  │   │  - Store token      │
        │  - Keep on login page  │   │  - Store user_id    │
        │  - Clear form          │   │  - Store role       │
        └───────────┬────────────┘   └──────────┬──────────┘
                    │                           │
        Retry login │                           │ 3. Redirect to dashboard
                    │                           │
                    └──────────────┬────────────┘
                                   │
                    ┌──────────────▼──────────┐
                    │  LOGGED IN               │
                    │  - Token in localStorage │
                    │  - User can access APIs  │
                    └──────────────┬──────────┘
                                   │
              ┌────────────────────┼───────────────────────┐
              │                    │                       │
        4a. Inactivity        4b. Manual logout      4c. Token expires
        (24+ hours)               (click logout)         (after 24 hours)
              │                    │                       │
              └────────────────────┼───────────────────────┘
                                   │
                    ┌──────────────▼──────────┐
                    │  LOGGING OUT             │
                    │  - Remove token from    │
                    │    localStorage         │
                    │  - Clear user_id        │
                    │  - Clear role           │
                    └──────────────┬──────────┘
                                   │
                                   │ Redirect to login page
                                   │
                    ┌──────────────▼──────────┐
                    │  NOT LOGGED IN           │
                    │  (Back to start)         │
                    └─────────────────────────┘
```

---

## 📊 Database Schema Relationships for Login

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATABASE RELATIONSHIPS                       │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────┐
│           USERS TABLE                │
│                                      │
│ id (PK)          ← Primary Key       │
│ username         ← Login identifier  │
│ email            ← Contact info      │
│ password_hash    ← Authentication    │
│ role             ← Authorization     │
│ created_at       ← Account created   │
│ last_login       ← Login tracking    │
└──────────────────────────────────────┘
         │                    │
         │ FK                 │ FK
         │ (1-to-many)        │ (1-to-many)
         │                    │
    ┌────▼──────────────┐    ┌────▼──────────────┐
    │  PROJECTS TABLE   │    │   SCANS TABLE     │
    │                  │    │                   │
    │ id (PK)          │    │ id (PK)           │
    │ name             │    │ scan_name         │
    │ user_id (FK)     │    │ target            │
    │ description      │    │ created_by (FK)   │
    │ created_at       │    │ project_id        │
    └────────────────────   └───────────────────┘
             │                     │
             │                     │ Each scan belongs to one project
             │                     │ Each scan is created by one user
             │                     │
         ┌───▼────────────────────────┐
         │  WHO CREATED THIS SCAN?    │
         │                            │
         │  User "admin" (id=1)       │
         │  Created scan_id=42        │
         │  In project_id=1           │
         │                            │
         │  Audit trail:              │
         │  - When? created_at        │
         │  - Who? created_by → user  │
         │  - What? scan details      │
         └────────────────────────────┘
```

---

## 🔐 Token Lifecycle

```
┌──────────────────────────────────────────────────────────────────┐
│                    TOKEN LIFECYCLE                               │
└──────────────────────────────────────────────────────────────────┘

CREATION (At Login)
    │
    ├─ Time: 2026-04-27 15:45:30
    ├─ User ID: 1
    ├─ Username: admin
    ├─ Role: admin
    ├─ Secret: 'dev-secret-key-change-in-production'
    │
    └─→ JWT Token Created
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
        eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjog
        ImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAi
        ZXhwIjogMTcxNzgyOTMzMH0.signature

STORAGE (In Browser)
    │
    ├─ localStorage.auth_token = "eyJ..."
    ├─ localStorage.user_id = "1"
    ├─ localStorage.username = "admin"
    ├─ localStorage.role = "admin"
    │
    └─→ Token persists across browser sessions

ACTIVE USE (24 Hours)
    │
    ├─ Every API request includes:
    │  Headers: {
    │      'Authorization': 'Bearer eyJ...',
    │      'Content-Type': 'application/json'
    │  }
    │
    ├─ Backend validates on each request:
    │  1. Check signature (not tampered)
    │  2. Check expiration (not expired)
    │  3. Extract user_id
    │  4. Proceed with request
    │
    └─→ Token valid for 24 hours from creation

EXPIRATION (After 24 Hours)
    │
    ├─ Expiration Time: 2026-04-28 15:45:30
    ├─ Current Time: 2026-04-28 15:45:31
    ├─ Status: EXPIRED
    │
    └─→ Token no longer valid

EXPIRED TOKEN HANDLING
    │
    ├─ User makes API request with expired token
    ├─ Backend checks: exp: 1717829330 < current_time
    ├─ Backend responds: 401 Unauthorized
    │
    └─→ Frontend:
        1. Detects 401 error
        2. Removes token from localStorage
        3. Redirects to login page
        4. Shows: "Session expired, please login again"

LOGOUT (Manual)
    │
    ├─ User clicks logout button
    ├─ JavaScript removes from localStorage:
    │  - auth_token
    │  - user_id
    │  - username
    │  - role
    │
    └─→ Token effectively destroyed
        (Still valid on server, but browser doesn't have it)

SECURITY NOTES
    │
    ├─ Token is stateless (no database lookup needed)
    ├─ Token signature prevents tampering
    ├─ Expiration prevents indefinite access
    ├─ localStorage accessible to JavaScript
    │  (XSS vulnerability - use secure cookies in production)
    ├─ Token should be sent in HTTP-only cookies (secure)
    │  (Currently uses localStorage - less secure)
    │
    └─→ Additional measures in production:
        - HTTPS only
        - HttpOnly flag on cookies
        - SameSite attribute
        - Refresh token for longer sessions
```

---

## 🌍 API Call With Authentication

```
┌──────────────────────────────────────────────────────────────────┐
│        HOW API CALLS USE AUTHENTICATION TOKEN                    │
└──────────────────────────────────────────────────────────────────┘

EXAMPLE: Get All Scans

BEFORE LOGIN (Currently - No authentication needed)
    │
    ├─ Request:
    │  GET /api/v1/scans
    │  Headers: {
    │      'Content-Type': 'application/json'
    │  }
    │
    └─ Response: 200 OK
       [all scans from database]

AFTER LOGIN (If implemented)
    │
    ├─ Request:
    │  GET /api/v1/scans
    │  Headers: {
    │      'Content-Type': 'application/json',
    │      'Authorization': 'Bearer eyJ...'
    │  }
    │
    ├─ Backend Processing:
    │  1. Check if Authorization header exists
    │  2. Extract token from "Bearer <token>"
    │  3. Verify token signature
    │  4. Check token not expired
    │  5. Extract user_id from token
    │  6. Query: SELECT * FROM scans WHERE created_by = ?
    │  7. Return only user's scans
    │
    └─ Response: 200 OK
       [scans created by this user only]

ERROR: Missing Token
    │
    ├─ Request:
    │  GET /api/v1/scans
    │  Headers: {
    │      'Content-Type': 'application/json'
    │      (no Authorization header)
    │  }
    │
    └─ Response: 401 Unauthorized
       {
           "error": "Missing authorization token"
       }

ERROR: Invalid Token
    │
    ├─ Request:
    │  GET /api/v1/scans
    │  Headers: {
    │      'Authorization': 'Bearer invalid.token.here'
    │  }
    │
    └─ Response: 401 Unauthorized
       {
           "error": "Invalid token signature"
       }

ERROR: Expired Token
    │
    ├─ Request:
    │  GET /api/v1/scans
    │  Headers: {
    │      'Authorization': 'Bearer eyJ...' (expired)
    │  }
    │
    ├─ Backend: Checks exp timestamp
    │  Current: 2026-04-28 16:00:00
    │  Token exp: 2026-04-28 15:45:30
    │  Status: EXPIRED
    │
    └─ Response: 401 Unauthorized
       {
           "error": "Token expired"
       }

JavaScript Implementation
    │
    └─ async function getScanData() {
        const token = localStorage.getItem('auth_token');

        const response = await fetch('/api/v1/scans', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.status === 401) {
            // Token invalid/expired
            localStorage.removeItem('auth_token');
            window.location.href = '/login.html';
            return;
        }

        const scans = await response.json();
        displayScans(scans);
    }
```

---

## 🔄 Login Error Scenarios

```
┌──────────────────────────────────────────────────────────────────┐
│            LOGIN ERROR HANDLING FLOWCHART                        │
└──────────────────────────────────────────────────────────────────┘

USER SUBMITS CREDENTIALS
    ↓
VALIDATION ERROR?
    ├─ Username empty? → Show "Username required" → Stop
    ├─ Password empty? → Show "Password required" → Stop
    ├─ Invalid format? → Show "Invalid format" → Stop
    └─ All valid ✓ → Continue
    ↓
SEND TO BACKEND
    ↓
BACKEND RECEIVES
    ├─ Parse JSON ✓
    ├─ Extract username
    ├─ Extract password
    └─ Continue
    ↓
DATABASE QUERY
    ├─ SELECT * FROM users WHERE username = 'admin'
    └─ Result?
        │
        ├─ NO RESULT (User not found)
        │  └─→ Return: 401 "Invalid username or password"
        │      (Generic message - don't reveal user doesn't exist)
        │      Frontend: Show error, focus on username field
        │
        └─ RESULT FOUND
           └─→ Compare passwords
               │
               ├─ PASSWORD MISMATCH
               │  └─→ Return: 401 "Invalid username or password"
               │      Frontend: Show error, focus on password field
               │      Log: Failed login attempt for user: admin
               │
               └─ PASSWORD MATCH ✓
                  └─→ Update last_login
                      Generate token
                      Return: 200 + token
```

---

## 🔑 Password Hashing Security (To Be Implemented)

```
┌──────────────────────────────────────────────────────────────────┐
│          PASSWORD HASHING FLOW (SECURITY BEST PRACTICE)          │
└──────────────────────────────────────────────────────────────────┘

CURRENT STATE (INSECURE)
    │
    ├─ Password stored: "admin123" (plain text)
    ├─ Comparison: submitted == stored
    ├─ Problem: If database compromised, passwords visible
    └─ Risk: HIGH

RECOMMENDED FLOW (SECURE)

REGISTRATION (When user creates account)
    │
    ├─ User enters password: "MyPassword123!"
    ├─ Generate salt: random_salt = "abcd1234efgh5678"
    ├─ Hash password + salt:
    │  hash = bcrypt("MyPassword123!" + "abcd1234efgh5678")
    │  result = "$2b$12$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ee8GyXuBRyG6c94W"
    │
    ├─ Store in database:
    │  INSERT INTO users (password_hash)
    │  VALUES ("$2b$12$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ee8GyXuBRyG6c94W")
    │
    └─ Database now safe - password not visible

LOGIN (When user authenticates)
    │
    ├─ User enters password: "MyPassword123!"
    ├─ Retrieve from DB:
    │  stored_hash = "$2b$12$R9h7cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ee8GyXuBRyG6c94W"
    │
    ├─ Hash submitted password with same salt:
    │  submitted_hash = bcrypt.verify(
    │      "MyPassword123!",
    │      stored_hash
    │  )
    │
    ├─ Compare:
    │  submitted_hash == stored_hash? YES ✓
    │
    ├─ Grant access: Generate token and login
    │
    └─ Even if database exposed, attacker can't reverse hash

WRONG PASSWORD
    │
    ├─ User enters: "WrongPassword!"
    ├─ Hash submission: bcrypt("WrongPassword!" + salt)
    ├─ Compare with stored hash
    ├─ Result: MISMATCH ✗
    └─ Deny access: 401 Unauthorized

KEY BENEFITS
    │
    ├─ Passwords never stored in plain text
    ├─ Same password = different hash each time (salt)
    ├─ Stolen database ≠ stolen passwords
    ├─ Brute force attacks computationally expensive
    └─ Industry standard (bcrypt, argon2)
```

---

## 📱 Frontend Template - Login Button Click Handler

```javascript
┌──────────────────────────────────────────────────────────────────┐
│              JAVASCRIPT LOGIN BUTTON HANDLER                     │
│                    (Step-by-Step Execution)                      │
└──────────────────────────────────────────────────────────────────┘

// FILE: frontend/js/login.js

document.getElementById('login-btn').addEventListener('click', async function(event) {
    // STEP 1: Prevent form default submission
    event.preventDefault();

    // STEP 2: Get form values from input fields
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // STEP 3: Show loading state
    const loginBtn = document.getElementById('login-btn');
    loginBtn.disabled = true;
    loginBtn.textContent = 'Logging in...';

    // STEP 4: Validate on frontend
    if (!username) {
        showError('Please enter your username');
        loginBtn.disabled = false;
        loginBtn.textContent = 'Login';
        return;
    }

    if (!password) {
        showError('Please enter your password');
        loginBtn.disabled = false;
        loginBtn.textContent = 'Login';
        return;
    }

    // STEP 5: Prepare request data
    const loginData = {
        username: username,
        password: password
    };

    // STEP 6: Make HTTP POST request to backend
    try {
        const response = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(loginData)
        });

        // STEP 7: Parse response
        const data = await response.json();

        // STEP 8: Check HTTP status code
        if (response.ok) {
            // SUCCESS (200 OK)
            console.log('Login successful', data);

            // STEP 9: Store token and user info in localStorage
            localStorage.setItem('auth_token', data.token);
            localStorage.setItem('user_id', data.user_id);
            localStorage.setItem('username', data.username);
            localStorage.setItem('role', data.role);

            // STEP 10: Show success message
            showSuccess(`Welcome, ${data.username}!`);

            // STEP 11: Redirect to dashboard
            setTimeout(() => {
                window.location.href = '/index.html';
            }, 1500);

        } else {
            // ERROR (401, 400, 500, etc.)
            console.error('Login failed', data);

            // STEP 12: Show error message to user
            showError(data.error || 'Login failed. Please try again.');

            // STEP 13: Clear sensitive fields
            document.getElementById('password').value = '';

            // STEP 14: Re-enable button
            loginBtn.disabled = false;
            loginBtn.textContent = 'Login';
        }

    } catch (error) {
        // NETWORK ERROR
        console.error('Network error:', error);
        showError('Network error. Is the server running?');
        loginBtn.disabled = false;
        loginBtn.textContent = 'Login';
    }
});

// HELPER FUNCTION: Display error
function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.color = 'red';
    errorDiv.style.display = 'block';
}

// HELPER FUNCTION: Display success
function showSuccess(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.color = 'green';
    errorDiv.style.display = 'block';
}

// EXECUTION TIMELINE WHEN USER CLICKS LOGIN BUTTON:
//
// T=0ms     | Event listener triggered
// T=5ms     | Get form values (username, password)
// T=10ms    | Validate inputs
// T=15ms    | Show "Logging in..." state
// T=20ms    | Create JSON payload
// T=25ms    | Send HTTP POST request
// T=30-100ms| Network transmission to server
// T=100ms   | Backend processes request (auth check, DB query)
// T=150ms   | Backend generates JWT token
// T=150-250ms| Network transmission back to browser
// T=250ms   | Browser receives response
// T=251ms   | Parse JSON response
// T=252ms   | Check if response.ok (status 200)
// T=253ms   | SUCCESS: Store token in localStorage
// T=254ms   | Show success message
// T=1500ms  | Redirect to dashboard
// T=1600ms  | New page loads
//
// TOTAL TIME: ~1.6 seconds
```

---

## 🎓 Summary

This document provides:

1. **Complete Sequence Diagram** - Shows all interactions from user click to final response
2. **Database Flow** - How data moves through the database during login
3. **State Machine** - How authentication state changes over time
4. **Schema Relationships** - How users relate to other tables
5. **Token Lifecycle** - From creation through expiration
6. **API Authentication** - How tokens are used in requests
7. **Error Handling** - All possible error scenarios
8. **Security Best Practices** - Password hashing (to be implemented)
9. **Code Templates** - JavaScript for button click handlers

All diagrams explain what WOULD happen if the login system were implemented, using the existing database infrastructure and configuration.
