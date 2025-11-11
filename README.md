# SSD Lab 08 - Secure Flask Application
## OWASP Secure Coding Practices Implementation

This Flask application demonstrates the implementation of 5 critical OWASP secure coding practices as required in Lab 08.

---

## 🔒 Security Features Implemented

### 1. **Secure Input Handling** (Prevents SQL Injection & XSS)
- **Implementation:** WTForms validators with custom validation functions
- **Techniques Used:**
  - `validate_no_sql_keywords()`: Blocks SQL keywords (SELECT, DROP, INSERT, etc.)
  - `validate_no_xss()`: Blocks XSS patterns (<script>, javascript:, etc.)
  - Regex validation for specific formats (email, phone, username)
  - Length validation on all inputs
  - Character set restrictions

### 2. **Parameterized Queries** (Prevents SQL Injection)
- **Implementation:** SQLAlchemy ORM
- **Why It Works:** 
  - All database queries use SQLAlchemy ORM methods (filter_by, query.all, etc.)
  - ORM automatically parameterizes queries
  - No raw SQL strings are used
  - User input never concatenated directly into SQL

### 3. **Session Management & CSRF Protection** (Prevents CSRF Attacks)
- **Implementation:** Flask-WTF with CSRF tokens
- **Configuration:**
  - `CSRFProtect(app)` enables CSRF protection
  - `{{ form.hidden_tag() }}` in all forms generates CSRF tokens
  - Secure cookie settings:
    - `SESSION_COOKIE_SECURE = True` (HTTPS only)
    - `SESSION_COOKIE_HTTPONLY = True` (prevents JavaScript access)
    - `SESSION_COOKIE_SAMESITE = 'Lax'` (prevents cross-site requests)
  - Session timeout: 30 minutes

### 4. **Secure Error Handling** (Prevents Information Disclosure)
- **Implementation:** Custom error pages with @app.errorhandler decorators
- **Error Pages Created:**
  - 404 (Page Not Found)
  - 500 (Internal Server Error)
  - 403 (Forbidden)
- **Security Benefits:**
  - No stack traces shown to users
  - No database error messages exposed
  - No file paths or system information revealed
  - Generic error messages prevent reconnaissance

### 5. **Secure Password Storage** (Prevents Weak Password Storage)
- **Implementation:** Flask-Bcrypt with strong password requirements
- **Features:**
  - Bcrypt hashing algorithm (industry standard)
  - Automatic salt generation
  - Password requirements enforced:
    - Minimum 8 characters
    - Uppercase letter required
    - Lowercase letter required
    - Number required
    - Special character required (@$!%*?&#)
  - Passwords never stored in plain text

---

## 📂 Project Structure

```
SSD LAB 08/
│
├── app.py                          # Main application file
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── secure_app.db                   # SQLite database (created on first run)
│
└── templates/
    ├── base.html                   # Base template
    ├── index.html                  # Home page
    ├── login.html                  # Login page with CSRF
    ├── register.html               # Registration page
    ├── contact.html                # Contact form
    ├── dashboard.html              # Dashboard (protected)
    └── errors/
        ├── 404.html                # Custom 404 page
        ├── 500.html                # Custom 500 page
        └── 403.html                # Custom 403 page
```

---

## 🚀 Installation & Setup

### Step 1: Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### Step 2: Run the Application
```powershell
python app.py
```

### Step 3: Access the Application
Open your browser and navigate to: `http://127.0.0.1:5000`

---

## 🧪 Testing Security Features

### Test 1: SQL Injection Prevention
1. Go to Login page
2. Try username: `admin' OR '1'='1--`
3. **Expected Result:** ❌ Error message "Invalid input detected"

### Test 2: XSS Prevention
1. Go to Contact form
2. Try name: `<script>alert('XSS')</script>`
3. **Expected Result:** ❌ Error message "Invalid characters detected"

### Test 3: CSRF Protection
1. Inspect any form in browser
2. Look for hidden input with name `csrf_token`
3. **Expected Result:** ✅ CSRF token present in all forms

### Test 4: Password Hashing
1. Register a new user
2. Check database: `sqlite3 secure_app.db "SELECT * FROM users;"`
3. **Expected Result:** ✅ Password is hashed (not plain text)

### Test 5: Error Handling
1. Visit non-existent page: `http://127.0.0.1:5000/nonexistent`
2. **Expected Result:** ✅ Custom 404 page (no stack trace)

---

## 📋 Code Highlights

### Input Validation Example (app.py)
```python
def validate_no_sql_keywords(form, field):
    """Validator to prevent SQL injection attempts"""
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', ...]
    data_upper = str(field.data).upper()
    for keyword in sql_keywords:
        if keyword in data_upper:
            raise ValidationError(f'Invalid input detected.')
```

### CSRF Protection Example (login.html)
```html
<form method="POST" action="{{ url_for('login') }}">
    {{ form.hidden_tag() }}  <!-- CSRF Token -->
    <!-- form fields -->
</form>
```

### Password Hashing Example (app.py)
```python
def set_password(self, password):
    """Hash password using bcrypt before storing"""
    self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
```

### Parameterized Query Example (app.py)
```python
# Safe: Using SQLAlchemy ORM (parameterized)
user = User.query.filter_by(username=form.username.data).first()

# NEVER do this (vulnerable to SQL injection):
# query = f"SELECT * FROM users WHERE username='{username}'"
```

---

## 📊 Security Checklist

- ✅ **Input Validation:** All forms use WTForms validators
- ✅ **SQL Injection Prevention:** SQLAlchemy ORM used throughout
- ✅ **XSS Prevention:** Custom validators block malicious scripts
- ✅ **CSRF Protection:** Flask-WTF CSRF tokens on all forms
- ✅ **Password Security:** Bcrypt hashing with strong requirements
- ✅ **Session Security:** Secure cookie flags enabled
- ✅ **Error Handling:** Custom error pages prevent info disclosure
- ✅ **No Hardcoded Credentials:** Secret key generated randomly

---

## 📖 OWASP References Used

1. **Input Validation:** https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
2. **SQL Injection Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
3. **CSRF Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
4. **Error Handling:** https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
5. **Password Storage:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## 👨‍💻 Lab Completed By
**Student Name:** [Your Name]  
**Course:** Cyber Security - SSD Lab Fall 2025  
**Instructor:** Mr. Usman Naeem  
**Lab:** 08 - Secure Coding Practices

---

## 📝 Notes for Grading

All 5 required security practices have been implemented:
1. ✅ Secure Input Handling
2. ✅ Parameterized Queries
3. ✅ Session Management & CSRF Protection
4. ✅ Secure Error Handling
5. ✅ Secure Password Storage

Additional security features included:
- Secure session configuration
- Generic error messages (prevents username enumeration)
- Strong password requirements
- Multiple validation layers
- Bootstrap UI for professional appearance
