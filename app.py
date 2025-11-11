from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError, Regexp
import re
import os
from datetime import timedelta

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.urandom(24)  # Generate random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security Settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # CSRF Protection enabled
bcrypt = Bcrypt(app)  # Password hashing


# ==================== MODELS ====================
class User(db.Model):
    """User model with secure password storage"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Stores hashed password
    
    def set_password(self, password):
        """Hash password using bcrypt before storing"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Verify password against hash"""
        return bcrypt.check_password_hash(self.password_hash, password)


class Contact(db.Model):
    """Contact model for user contact information"""
    __tablename__ = 'contacts'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Contact {self.name}>'


# ==================== CUSTOM VALIDATORS ====================
def validate_no_sql_keywords(form, field):
    """Validator to prevent SQL injection attempts"""
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 
                    'ALTER', 'EXEC', 'EXECUTE', 'UNION', 'OR', '--', ';', '/*', '*/',
                    'XP_', 'SP_', 'SCRIPT', 'JAVASCRIPT', 'ONERROR', 'ONLOAD']
    
    data_upper = str(field.data).upper()
    for keyword in sql_keywords:
        if keyword in data_upper:
            raise ValidationError(f'Invalid input detected. Please remove special keywords.')


def validate_no_xss(form, field):
    """Validator to prevent XSS attacks"""
    xss_patterns = ['<script', '</script>', 'javascript:', 'onerror=', 'onload=', 
                    '<iframe', '<object', '<embed', 'eval(', 'alert(']
    
    data_lower = str(field.data).lower()
    for pattern in xss_patterns:
        if pattern in data_lower:
            raise ValidationError('Invalid characters detected in input.')


# ==================== FORMS WITH VALIDATION ====================
class LoginForm(FlaskForm):
    """Secure login form with input validation"""
    username = StringField('Username', 
                          validators=[
                              DataRequired(message='Username is required'),
                              Length(min=3, max=80, message='Username must be between 3 and 80 characters'),
                              Regexp('^[A-Za-z0-9_]+$', message='Username must contain only letters, numbers, and underscores'),
                              validate_no_sql_keywords,
                              validate_no_xss
                          ])
    
    password = PasswordField('Password',
                            validators=[
                                DataRequired(message='Password is required'),
                                Length(min=8, message='Password must be at least 8 characters')
                            ])
    
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    """Secure registration form with input validation"""
    username = StringField('Username', 
                          validators=[
                              DataRequired(message='Username is required'),
                              Length(min=3, max=80, message='Username must be between 3 and 80 characters'),
                              Regexp('^[A-Za-z0-9_]+$', message='Username must contain only letters, numbers, and underscores'),
                              validate_no_sql_keywords,
                              validate_no_xss
                          ])
    
    email = StringField('Email',
                       validators=[
                           DataRequired(message='Email is required'),
                           Email(message='Please enter a valid email address'),
                           Length(max=120),
                           validate_no_sql_keywords,
                           validate_no_xss
                       ])
    
    password = PasswordField('Password',
                            validators=[
                                DataRequired(message='Password is required'),
                                Length(min=8, message='Password must be at least 8 characters'),
                                Regexp('^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[@$!%*?&#])', 
                                      message='Password must contain uppercase, lowercase, number, and special character')
                            ])
    
    submit = SubmitField('Register')


class ContactForm(FlaskForm):
    """Secure contact form with comprehensive input validation"""
    name = StringField('Full Name',
                      validators=[
                          DataRequired(message='Name is required'),
                          Length(min=2, max=100, message='Name must be between 2 and 100 characters'),
                          Regexp('^[A-Za-z ]+$', message='Name must contain only letters and spaces'),
                          validate_no_sql_keywords,
                          validate_no_xss
                      ])
    
    email = StringField('Email',
                       validators=[
                           DataRequired(message='Email is required'),
                           Email(message='Please enter a valid email address'),
                           Length(max=120),
                           validate_no_sql_keywords,
                           validate_no_xss
                       ])
    
    phone = StringField('Phone Number',
                       validators=[
                           DataRequired(message='Phone number is required'),
                           Regexp(r'^[0-9+\-() ]+$', message='Phone number can only contain numbers, +, -, (, ), and spaces'),
                           Length(min=10, max=20, message='Phone number must be between 10 and 20 characters'),
                           validate_no_sql_keywords
                       ])
    
    address = StringField('Address',
                         validators=[
                             DataRequired(message='Address is required'),
                             Length(min=5, max=200, message='Address must be between 5 and 200 characters'),
                             validate_no_sql_keywords,
                             validate_no_xss
                         ])
    
    message = TextAreaField('Message',
                           validators=[
                               Length(max=500, message='Message must not exceed 500 characters'),
                               validate_no_sql_keywords,
                               validate_no_xss
                           ])
    
    submit = SubmitField('Submit')


# ==================== ROUTES ====================
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login route with CSRF protection"""
    form = LoginForm()
    
    if form.validate_on_submit():
        # Using parameterized query through SQLAlchemy ORM
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            # Secure session management
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Generic error message to prevent username enumeration
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Secure registration route with password hashing"""
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Check if user already exists using parameterized query
        existing_user = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()
        
        if existing_user:
            flash('Username already exists', 'danger')
        elif existing_email:
            flash('Email already registered', 'danger')
        else:
            # Create new user with hashed password
            new_user = User(username=form.username.data, email=form.email.data)
            new_user.set_password(form.password.data)  # Password is hashed here
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Secure contact form route with input validation and sanitization"""
    form = ContactForm()
    
    if form.validate_on_submit():
        # Using SQLAlchemy ORM (parameterized queries by default)
        new_contact = Contact(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            address=form.address.data,
            message=form.message.data if form.message.data else ''
        )
        
        db.session.add(new_contact)
        db.session.commit()
        
        flash('Contact information submitted successfully!', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html', form=form)


@app.route('/dashboard')
def dashboard():
    """Dashboard page - requires login"""
    if 'user_id' not in session:
        flash('Please login to access the dashboard', 'warning')
        return redirect(url_for('login'))
    
    # Using parameterized query through SQLAlchemy ORM
    contacts = Contact.query.all()
    return render_template('dashboard.html', contacts=contacts)


@app.route('/logout')
def logout():
    """Secure logout - clears session"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page - prevents information disclosure"""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page - prevents information disclosure"""
    # Log the error internally but don't expose details to user
    app.logger.error(f'Internal Server Error: {e}')
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    """Custom 403 error page"""
    return render_template('errors/403.html'), 403


# ==================== DATABASE INITIALIZATION ====================
def init_db():
    """Initialize database"""
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")


if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run in debug mode for development (disable in production)
    app.run(debug=True, host='127.0.0.1', port=5000)
