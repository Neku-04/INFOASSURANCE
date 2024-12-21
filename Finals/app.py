from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

db_config = {
    'user': 'root',
    'password': 'Nikko@25',
    'host': 'localhost',
    'database': 'food_inventory'
}

def get_db_connection():
    """Establish a connection to the database."""
    return mysql.connector.connect(**db_config)

def allowed_file(filename):
    """Check if the uploaded file is allowed based on its extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class User(UserMixin):
    def __init__(self, id, username, password, first_name, last_name, email, phone, role, approved, profile_pic):
        self.id = id
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.role = role
        self.approved = approved
        self.profile_pic = profile_pic

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['password'], user['first_name'], user['last_name'], user['email'], user['phone'], user['role'], user['approved'], user.get('profile_pic'))
    return None

def create_default_admin():
    """Create a default admin user if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE username = %s', ('neku_08',))
    admin = cursor.fetchone()
    if not admin:
        hashed_password = bcrypt.generate_password_hash('nikko').decode('utf-8')
        cursor.execute('INSERT INTO users (first_name, last_name, email, phone, username, password, role, approved, profile_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)', 
                       ('Default', 'Admin', 'nipapa@mycspc.edu.ph', '0000000000', 'neku_08', hashed_password, 'admin', True, None))
        conn.commit()
    cursor.close()
    conn.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        # Collect user information from the form
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        profile_pic = None
        
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic = filename
            else:
                flash('Invalid file type. Please upload a PNG, JPG, JPEG, or GIF file.', 'error')
                return render_template('register.html')
        else:
            flash('Profile picture is required.', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if username, email, or phone already exists in users or pending_users
        cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s OR phone = %s', (username, email, phone))
        existing_user = cursor.fetchone()
        cursor.execute('SELECT * FROM pending_users WHERE username = %s OR email = %s OR phone = %s', (username, email, phone))
        existing_pending_user = cursor.fetchone()
        
        if existing_user or existing_pending_user:
            # Handle duplicate user information
            if existing_user and existing_user['username'] == username or existing_pending_user and existing_pending_user['username'] == username:
                flash('Username already exists. Please choose a different one.', 'error')
            elif existing_user and existing_user['email'] == email or existing_pending_user and existing_pending_user['email'] == email:
                flash('Email already registered. Please use a different email.', 'error')
            elif existing_user and existing_user['phone'] == phone or existing_pending_user and existing_pending_user['phone'] == phone:
                flash('Mobile phone already registered. Please use a different phone number.', 'error')
            cursor.close()
            conn.close()
            return render_template('register.html')
        
        # Hash the password and store the user in the pending_users table
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute('INSERT INTO pending_users (first_name, last_name, email, phone, username, password, role, profile_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', 
                       (first_name, last_name, email, phone, username, hashed_password, role, profile_pic))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Account created successfully! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        # Collect login information from the form
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and bcrypt.check_password_hash(user['password'], password):
            if user['approved']:
                # Log in the user if approved
                login_user(User(user['id'], user['username'], user['password'], user['first_name'], user['last_name'], user['email'], user['phone'], user['role'], user['approved'], user.get('profile_pic')))
                return redirect(url_for('index'))
            else:
                flash('Your account is not approved yet. Please wait for admin approval.', 'error')
        else:
            flash('Login Unsuccessful. Please check username and password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Display the main dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    if current_user.role == 'admin':
        cursor.execute('SELECT * FROM food_items WHERE user_id = %s', (current_user.id,))
        food_items = cursor.fetchall()
        cursor.execute('SELECT COUNT(*) AS pending_count FROM pending_users')
        pending_count = cursor.fetchone()['pending_count']
        if pending_count > 0:
            flash(f'You have {pending_count} pending user approvals.', 'info')
    else:
        cursor.execute('SELECT * FROM food_items WHERE user_id IN (SELECT id FROM users WHERE role = "admin")')
        food_items = cursor.fetchall()
    cursor.close()
    conn.close()
    if current_user.role == 'admin':
        return render_template('index.html', food_items=food_items)
    else:
        return render_template('view_products.html', food_items=food_items)

@app.route('/add', methods=['POST'])
@login_required
def add_food_item():
    """Handle adding a new food item."""
    if current_user.role != 'admin':
        flash('You do not have permission to add food items.', 'error')
        return redirect(url_for('index'))
    
    name = request.form['name']
    quantity = request.form['quantity']
    expiration_date = request.form['expiration_date']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO food_items (name, quantity, expiration_date, added_date, user_id) VALUES (%s, %s, %s, %s, %s)',
                   (name, quantity, expiration_date, datetime.datetime.utcnow(), current_user.id))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Food item added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
@login_required
def delete_food_item(id):
    """Handle deleting a food item."""
    if current_user.role != 'admin':
        flash('You do not have permission to delete food items.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM food_items WHERE id = %s AND user_id = %s', (id, current_user.id))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Food item deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_food_item(id):
    """Handle updating a food item."""
    if current_user.role != 'admin':
        flash('You do not have permission to update food items.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM food_items WHERE id = %s AND user_id = %s', (id, current_user.id))
    food_item = cursor.fetchone()
    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        expiration_date = request.form['expiration_date']
        cursor.execute('UPDATE food_items SET name = %s, quantity = %s, expiration_date = %s WHERE id = %s AND user_id = %s',
                       (name, quantity, expiration_date, id, current_user.id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Food item updated successfully!', 'success')
        return redirect(url_for('index'))
    cursor.close()
    conn.close()
    return render_template('update.html', food_item=food_item)

@app.route('/admin/approve_users', methods=['GET', 'POST'])
@login_required
def approve_users():
    """Handle approving pending users."""
    if current_user.role != 'admin':
        flash('You do not have permission to approve users.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        user_id = request.form['user_id']
        cursor.execute('SELECT * FROM pending_users WHERE id = %s', (user_id,))
        pending_user = cursor.fetchone()
        if pending_user:
            cursor.execute('INSERT INTO users (first_name, last_name, email, phone, username, password, role, approved, profile_pic) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)', 
                           (pending_user['first_name'], pending_user['last_name'], pending_user['email'], pending_user['phone'], pending_user['username'], pending_user['password'], pending_user['role'], True, pending_user.get('profile_pic')))
            cursor.execute('DELETE FROM pending_users WHERE id = %s', (user_id,))
            conn.commit()
            flash('User approved successfully!', 'success')
    
    cursor.execute('SELECT * FROM pending_users')
    pending_users = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('approve_users.html', pending_users=pending_users)

@app.route('/admin/delete_pending_user/<int:user_id>', methods=['POST'])
@login_required
def delete_pending_user(user_id):
    """Handle deleting a pending user."""
    if current_user.role != 'admin':
        flash('You do not have permission to delete users.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pending_users WHERE id = %s', (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Pending user deleted successfully!', 'success')
    return redirect(url_for('approve_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Handle deleting an approved user."""
    if current_user.role != 'admin':
        flash('You do not have permission to delete users.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('view_users'))

@app.route('/admin/view_users')
@login_required
def view_users():
    """Display a list of approved users."""
    if current_user.role != 'admin':
        flash('You do not have permission to view users.', 'error')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE approved = TRUE')
    approved_users = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('view_users.html', approved_users=approved_users)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Handle viewing and updating user profile."""
    if request.method == 'POST':
        # Collect profile information from the form
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        profile_pic = current_user.profile_pic
        
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic = filename
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET first_name = %s, last_name = %s, email = %s, phone = %s, profile_pic = %s WHERE id = %s',
                       (first_name, last_name, email, phone, profile_pic, current_user.id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

if __name__ == '__main__':
    create_default_admin()
    app.run(debug=True)