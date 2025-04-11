import os
import sys
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, g, redirect, url_for, request, session, flash, Blueprint, jsonify

# Enable debug mode
DEBUG = True

# Database configuration
DATABASE = 'database.db'

# Database functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()
        print("Database initialized successfully")

def query_db(query, args=(), one=False):
    if DEBUG:
        print(f"Executing query: {query} with args: {args}")
    try:
        cur = get_db().execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"Database error: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        return None if one else []

def insert_db(query, args=()):
    if DEBUG:
        print(f"Executing insert: {query} with args: {args}")
    try:
        db = get_db()
        cur = db.execute(query, args)
        db.commit()
        last_id = cur.lastrowid
        cur.close()
        return last_id
    except Exception as e:
        print(f"Database error: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        return None

def update_db(query, args=()):
    if DEBUG:
        print(f"Executing update: {query} with args: {args}")
    try:
        db = get_db()
        cur = db.execute(query, args)
        db.commit()
        affected = cur.rowcount
        cur.close()
        return affected
    except Exception as e:
        print(f"Database error: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        return 0

# Utility functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('index'))
        if not session.get('is_admin', False):
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Add the context processor here
@app.context_processor
def utility_processor():
    return dict(
        query_db=query_db,
        now=datetime.now()  # Add current datetime to all templates
    )

# Set template folder explicitly and print for debugging
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
print(f"Template folder: {app.template_folder}")

# Check if templates exist before requests
@app.before_request
def check_templates():
    if not os.path.exists(app.template_folder):
        print(f"WARNING: Template folder does not exist: {app.template_folder}")
        os.makedirs(app.template_folder)
    
    # Check for specific templates
    templates_to_check = [
        'base.html',
        'index.html',
        'admin/dashboard.html',
        'admin/login.html',
        'admin/client_details.html',
        'admin/add_client.html',
        'admin/edit_client.html',
        'admin/add_itr.html',
        'admin/referrals.html',
        'admin/notifications.html',
        'client/dashboard.html',
        'client/login.html',
        'client/profile.html',
        'client/referral.html',
        'register.html',
        '404.html',
        '500.html'
    ]
    
    for template in templates_to_check:
        template_path = os.path.join(app.template_folder, template)
        if not os.path.exists(template_path):
            parent_dir = os.path.dirname(template_path)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            print(f"WARNING: Template does not exist: {template_path}")

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Debug information
        print(f"Admin login attempt: {username}")
        
        try:
            # For simplicity, we're using plain text passwords for this example
            # In a production environment, you should use proper password hashing
            user = query_db('SELECT * FROM users WHERE username = ? AND password = ?', 
                        [username, password], one=True)
            
            if user and user['is_admin'] == 1:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = True
                flash('Login successful!', 'success')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Invalid username or password', 'error')
        except Exception as e:
            print(f"Error during admin login: {str(e)}")
            flash(f'An error occurred during login. Please try again.', 'error')

    return render_template('admin/login.html')

@admin_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    try:
        clients = query_db('SELECT * FROM clients')
        if DEBUG:
            print(f"Found {len(clients)} clients")
        
        # Get unread referrals count
        unread_referrals_count = query_db(
            'SELECT COUNT(*) as count FROM referrals WHERE is_reviewed = 0', 
            one=True
        )
        
        # Get admin notifications
        admin_notifications = query_db(
            'SELECT * FROM admin_notifications WHERE is_read = 0 ORDER BY created_at DESC'
        )
        
        return render_template('admin/dashboard.html', 
                              clients=clients, 
                              unread_referrals_count=unread_referrals_count['count'] if unread_referrals_count else 0,
                              admin_notifications=admin_notifications)
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}", 'error')
        if DEBUG:
            import traceback
            traceback.print_exc()
        return redirect(url_for('index'))

@admin_bp.route('/client/<int:client_id>')
@admin_required
def client_details(client_id):
    client = query_db('SELECT * FROM clients WHERE id = ?', [client_id], one=True)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('admin.dashboard'))

    itr_records = query_db('SELECT * FROM itr_records WHERE client_id = ? ORDER BY year DESC', [client_id])
    
    # Get referrals made by this client
    referrals = query_db(
        '''SELECT r.*, c.full_name as referred_name 
           FROM referrals r 
           LEFT JOIN clients c ON r.referred_client_id = c.id 
           WHERE r.client_id = ? 
           ORDER BY r.created_at DESC''', 
        [client_id]
    )
    
    return render_template('admin/client_details.html', 
                          client=client, 
                          itr_records=itr_records,
                          referrals=referrals)

@admin_bp.route('/client/add', methods=['GET', 'POST'])
@admin_required
def add_new_client():
    if request.method == 'POST':
        # Create user account first
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        if query_db('SELECT * FROM users WHERE username = ?', [username], one=True):
            flash('Username already exists', 'error')
            return render_template('admin/add_client.html')
        
        # Add user with plain text password
        user_id = insert_db(
            'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
            [username, password, 0]
        )
        
        if not user_id:
            flash('Error creating user account', 'error')
            return render_template('admin/add_client.html')
        
        # Add client details
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        pan_number = request.form['pan_number']
        
        # Generate referral code
        referral_code = str(uuid.uuid4())[:8]
        
        client_id = insert_db(
            'INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [user_id, full_name, email, phone, address, pan_number, referral_code]
        )
        
        if not client_id:
            flash('Error creating client profile', 'error')
            return render_template('admin/add_client.html')
        
        # Add welcome notification
        insert_db(
            'INSERT INTO notifications (client_id, message) VALUES (?, ?)',
            [client_id, f"Welcome to the ITR Management System, {full_name}!"]
        )
        
        flash('Client added successfully', 'success')
        return redirect(url_for('admin.dashboard'))

    return render_template('admin/add_client.html')

@admin_bp.route('/client/<int:client_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_client(client_id):
    client = query_db('SELECT * FROM clients WHERE id = ?', [client_id], one=True)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        pan_number = request.form['pan_number']
        
        result = update_db(
            'UPDATE clients SET full_name = ?, email = ?, phone = ?, address = ?, pan_number = ? WHERE id = ?',
            [full_name, email, phone, address, pan_number, client_id]
        )
        
        if result:
            flash('Client updated successfully', 'success')
        else:
            flash('Error updating client', 'error')
        
        return redirect(url_for('admin.client_details', client_id=client_id))

    return render_template('admin/edit_client.html', client=client)

@admin_bp.route('/client/<int:client_id>/add_itr', methods=['GET', 'POST'])
@admin_required
def add_new_itr(client_id):
    client = query_db('SELECT * FROM clients WHERE id = ?', [client_id], one=True)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        itr_type = request.form['itr_type']
        year = request.form['year']
        status = request.form['status']
        filing_date = request.form.get('filing_date', None)
        
        # Handle document upload if provided
        document_path = None
        if 'document' in request.files and request.files['document'].filename:
            try:
                from werkzeug.utils import secure_filename
                file = request.files['document']
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(app.root_path, 'static', 'uploads')
                
                # Create upload folder if it doesn't exist
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                document_path = f'/static/uploads/{filename}'
            except Exception as e:
                flash(f'Error uploading document: {str(e)}', 'error')
                if DEBUG:
                    import traceback
                    traceback.print_exc()
        
        record_id = insert_db(
            'INSERT INTO itr_records (client_id, itr_type, year, status, filing_date, document_path) VALUES (?, ?, ?, ?, ?, ?)',
            [client_id, itr_type, year, status, filing_date, document_path]
        )
        
        if record_id:
            # Add notification
            insert_db(
                'INSERT INTO notifications (client_id, message) VALUES (?, ?)',
                [client_id, f"Your {itr_type} for {year} has been added with status: {status}"]
            )
            
            flash('ITR record added successfully', 'success')
        else:
            flash('Error adding ITR record', 'error')
        
        return redirect(url_for('admin.client_details', client_id=client_id))

    return render_template('admin/add_itr.html', client=client)

@admin_bp.route('/itr/<int:record_id>/update', methods=['POST'])
@admin_required
def update_itr(record_id):
    status = request.form['status']
    filing_date = request.form.get('filing_date', None)

    # Get client_id and record details for notification
    record = query_db('SELECT * FROM itr_records WHERE id = ?', [record_id], one=True)

    if record:
        result = update_db(
            'UPDATE itr_records SET status = ?, filing_date = ? WHERE id = ?',
            [status, filing_date, record_id]
        )
        
        if result:
            # Add notification
            insert_db(
                'INSERT INTO notifications (client_id, message) VALUES (?, ?)',
                [record['client_id'], f"Your {record['itr_type']} for {record['year']} status has been updated to: {status}"]
            )
            
            flash('ITR status updated successfully', 'success')
        else:
            flash('Error updating ITR status', 'error')
    else:
        flash('Record not found', 'error')

    return redirect(request.referrer or url_for('admin.dashboard'))

@admin_bp.route('/client/<int:client_id>/notify', methods=['POST'])
@admin_required
def send_notification(client_id):
    message = request.form['message']

    if message:
        result = insert_db(
            'INSERT INTO notifications (client_id, message) VALUES (?, ?)',
            [client_id, message]
        )
        
        if result:
            flash('Notification sent successfully', 'success')
        else:
            flash('Error sending notification', 'error')
    else:
        flash('Message cannot be empty', 'error')

    return redirect(url_for('admin.client_details', client_id=client_id))

@admin_bp.route('/referrals')
@admin_required
def referrals():
    # Get all referrals with client and referred person details
    referrals = query_db(
        '''SELECT r.*, c.full_name as client_name, 
           CASE WHEN r.referred_client_id IS NOT NULL THEN rc.full_name ELSE r.referred_name END as referred_name,
           CASE WHEN r.referred_client_id IS NOT NULL THEN 1 ELSE 0 END as is_registered
           FROM referrals r 
           JOIN clients c ON r.client_id = c.id
           LEFT JOIN clients rc ON r.referred_client_id = rc.id
           ORDER BY r.created_at DESC'''
    )
    
    return render_template('admin/referrals.html', referrals=referrals)

@admin_bp.route('/referral/<int:referral_id>/review', methods=['POST'])
@admin_required
def review_referral(referral_id):
    # Mark referral as reviewed
    update_db(
        'UPDATE referrals SET is_reviewed = 1 WHERE id = ?',
        [referral_id]
    )
    
    flash('Referral marked as reviewed', 'success')
    return redirect(url_for('admin.referrals'))

@admin_bp.route('/notifications')
@admin_required
def notifications():
    # Get all admin notifications
    notifications = query_db(
        'SELECT * FROM admin_notifications ORDER BY created_at DESC'
    )
    
    # Mark all as read
    update_db(
        'UPDATE admin_notifications SET is_read = 1'
    )
    
    return render_template('admin/notifications.html', notifications=notifications)

# Create client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

@client_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Debug information
        print(f"Client login attempt: {username}")
        
        try:
            # For simplicity, we're using plain text passwords for this example
            # In a production environment, you should use proper password hashing
            user = query_db('SELECT * FROM users WHERE username = ? AND password = ?', 
                        [username, password], one=True)
            
            if user and user['is_admin'] == 0:  # Make sure it's a client, not admin
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = False
                
                # Get client info
                client = query_db('SELECT * FROM clients WHERE user_id = ?', [user['id']], one=True)
                if client:
                    session['client_id'] = client['id']
                
                flash('Login successful!', 'success')
                return redirect(url_for('client.dashboard'))
            else:
                flash('Invalid username or password', 'error')
        except Exception as e:
            print(f"Error during client login: {str(e)}")
            flash(f'An error occurred during login. Please try again.', 'error')

    return render_template('client/login.html')

@client_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@client_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    client = query_db('SELECT * FROM clients WHERE user_id = ?', [user_id], one=True)

    if not client:
        flash('Client profile not found', 'error')
        return redirect(url_for('index'))

    itr_records = query_db('SELECT * FROM itr_records WHERE client_id = ? ORDER BY year DESC', [client['id']])
    notifications = query_db('SELECT * FROM notifications WHERE client_id = ? ORDER BY created_at DESC', [client['id']])
    
    # Get referrals made by this client
    referrals = query_db(
        '''SELECT r.*, 
           CASE WHEN r.referred_client_id IS NOT NULL THEN 1 ELSE 0 END as is_registered
           FROM referrals r 
           WHERE r.client_id = ? 
           ORDER BY r.created_at DESC''', 
        [client['id']]
    )
    
    # Check if referral_code exists in the client record
    # Fix: Use try/except instead of .get() method
    try:
        referral_code = client['referral_code']
    except (KeyError, IndexError):
        referral_code = None
    
    # Generate referral URL if not already present
    if not referral_code:
        referral_code = str(uuid.uuid4())[:8]
        update_db(
            'UPDATE clients SET referral_code = ? WHERE id = ?',
            [referral_code, client['id']]
        )
        # Refresh client data
        client = query_db('SELECT * FROM clients WHERE user_id = ?', [user_id], one=True)
    
    # Create the full referral URL
    referral_url = request.host_url + 'refer/' + client['referral_code']

    return render_template('client/dashboard.html', 
                          client=client, 
                          itr_records=itr_records, 
                          notifications=notifications,
                          referrals=referrals,
                          referral_url=referral_url)

@client_bp.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')
    client = query_db('SELECT * FROM clients WHERE user_id = ?', [user_id], one=True)

    if not client:
        flash('Client profile not found', 'error')
        return redirect(url_for('index'))

    return render_template('client/profile.html', client=client)

@client_bp.route('/notification/<int:notification_id>/read', methods=['POST'])
@login_required
def read_notification(notification_id):
    update_db(
        'UPDATE notifications SET is_read = 1 WHERE id = ?',
        [notification_id]
    )
    return redirect(url_for('client.dashboard'))

@client_bp.route('/refer', methods=['GET', 'POST'])
@login_required
def refer():
    user_id = session.get('user_id')
    client = query_db('SELECT * FROM clients WHERE user_id = ?', [user_id], one=True)

    if not client:
        flash('Client profile not found', 'error')
        return redirect(url_for('index'))
    
    # Generate referral URL if not already present
    # Fix: Use try/except instead of .get() method
    try:
        referral_code = client['referral_code']
        if not referral_code:  # Handle empty string case
            raise KeyError
    except (KeyError, IndexError):
        referral_code = str(uuid.uuid4())[:8]
        update_db(
            'UPDATE clients SET referral_code = ? WHERE id = ?',
            [referral_code, client['id']]
        )
        # Refresh client data
        client = query_db('SELECT * FROM clients WHERE user_id = ?', [user_id], one=True)
    
    # Create the full referral URL
    referral_url = request.host_url + 'refer/' + client['referral_code']
    
    if request.method == 'POST':
        referred_name = request.form['referred_name']
        referred_email = request.form['referred_email']
        referred_phone = request.form['referred_phone']
        
        # Add referral to database
        referral_id = insert_db(
            '''INSERT INTO referrals 
               (client_id, referred_name, referred_email, referred_phone) 
               VALUES (?, ?, ?, ?)''',
            [client['id'], referred_name, referred_email, referred_phone]
        )
        
        if referral_id:
            # Add admin notification
            insert_db(
                '''INSERT INTO admin_notifications 
                   (message, type, related_id) 
                   VALUES (?, ?, ?)''',
                [f"{client['full_name']} has referred {referred_name} ({referred_email})", 
                 'referral', 
                 referral_id]
            )
            
            flash('Referral added successfully! We will contact them soon.', 'success')
            return redirect(url_for('client.dashboard'))
        else:
            flash('Error adding referral', 'error')
    
    # Get previous referrals
    referrals = query_db(
        '''SELECT r.*, 
           CASE WHEN r.referred_client_id IS NOT NULL THEN 1 ELSE 0 END as is_registered
           FROM referrals r 
           WHERE r.client_id = ? 
           ORDER BY r.created_at DESC''', 
        [client['id']]
    )
    
    return render_template('client/referral.html', 
                          client=client, 
                          referral_url=referral_url,
                          referrals=referrals)

@client_bp.route('/copy-referral-url', methods=['POST'])
@login_required
def copy_referral_url():
    # This is just an API endpoint to acknowledge the copy action
    # The actual copying is done client-side with JavaScript
    return jsonify({'success': True})

# Register blueprints
app.register_blueprint(admin_bp)
app.register_blueprint(client_bp)

# Public routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/refer/<referral_code>')
def process_referral(referral_code):
    # Find the client with this referral code
    client = query_db('SELECT * FROM clients WHERE referral_code = ?', [referral_code], one=True)
    
    if not client:
        flash('Invalid referral link', 'error')
        return redirect(url_for('index'))
    
    # Store the referral code in session for later use during registration
    session['referral_code'] = referral_code
    session['referrer_id'] = client['id']
    
    flash(f"You've been referred by {client['full_name']}! Please register to continue.", 'info')
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if user was referred
    referrer_id = session.get('referrer_id')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form.get('address', '')
        pan_number = request.form.get('pan_number', '')
        
        # Check if username or email already exists
        if query_db('SELECT * FROM users WHERE username = ?', [username], one=True):
            flash('Username already exists', 'error')
            return render_template('register.html', referrer_id=referrer_id)
        
        if query_db('SELECT * FROM clients WHERE email = ?', [email], one=True):
            flash('Email already exists', 'error')
            return render_template('register.html', referrer_id=referrer_id)
        
        # Create user account
        user_id = insert_db(
            'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
            [username, password, 0]
        )
        
        if not user_id:
            flash('Error creating user account', 'error')
            return render_template('register.html', referrer_id=referrer_id)
        
        # Generate referral code
        referral_code = str(uuid.uuid4())[:8]
        
        # Create client profile
        client_id = insert_db(
            'INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [user_id, full_name, email, phone, address, pan_number, referral_code]
        )
        
        if not client_id:
            flash('Error creating client profile', 'error')
            return render_template('register.html', referrer_id=referrer_id)
        
        # If this was a referral, update the referral record
        if referrer_id:
            # Check if there's an existing referral with this email
            referral = query_db(
                'SELECT * FROM referrals WHERE client_id = ? AND referred_email = ?',
                [referrer_id, email],
                one=True
            )
            
            if referral:
                # Update existing referral
                update_db(
                    'UPDATE referrals SET referred_client_id = ? WHERE id = ?',
                    [client_id, referral['id']]
                )
            else:
                # Create new referral record
                referral_id = insert_db(
                    '''INSERT INTO referrals 
                       (client_id, referred_name, referred_email, referred_phone, referred_client_id) 
                       VALUES (?, ?, ?, ?, ?)''',
                    [referrer_id, full_name, email, phone, client_id]
                )
            
            # Notify the referrer
            insert_db(
                'INSERT INTO notifications (client_id, message) VALUES (?, ?)',
                [referrer_id, f"Your referral {full_name} has registered successfully!"]
            )
            
            # Add admin notification
            insert_db(
                '''INSERT INTO admin_notifications 
                   (message, type, related_id) 
                   VALUES (?, ?, ?)''',
                [f"New registration: {full_name} was referred by client #{referrer_id}", 
                 'registration', 
                 client_id]
            )
            
            # Clear referral session data
            session.pop('referral_code', None)
            session.pop('referrer_id', None)
        else:
            # Add admin notification for non-referred registration
            insert_db(
                '''INSERT INTO admin_notifications 
                   (message, type, related_id) 
                   VALUES (?, ?, ?)''',
                [f"New registration: {full_name} registered directly", 
                 'registration', 
                 client_id]
            )
        
        # Add welcome notification
        insert_db(
            'INSERT INTO notifications (client_id, message) VALUES (?, ?)',
            [client_id, f"Welcome to the ITR Management System, {full_name}!"]
        )
        
        flash('Registration successful! Please login to continue.', 'success')
        return redirect(url_for('client.login'))
    
    return render_template('register.html', referrer_id=referrer_id)

@app.teardown_appcontext
def close_connection(exception):
    close_db(exception)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Create schema.sql if it doesn't exist
def create_schema_file():
    if not os.path.exists('schema.sql'):
        schema_content = '''
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS itr_records;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS admin_notifications;
DROP TABLE IF EXISTS referrals;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    address TEXT,
    pan_number TEXT UNIQUE,
    referral_code TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE itr_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    itr_type TEXT NOT NULL,
    year TEXT NOT NULL,
    status TEXT NOT NULL,
    filing_date TIMESTAMP,
    document_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id)
);

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id)
);

CREATE TABLE admin_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT NOT NULL,
    type TEXT NOT NULL,
    related_id INTEGER,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    referred_name TEXT NOT NULL,
    referred_email TEXT NOT NULL,
    referred_phone TEXT,
    referred_client_id INTEGER,
    is_reviewed BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id),
    FOREIGN KEY (referred_client_id) REFERENCES clients (id)
);

-- Insert admin user with plain text password
INSERT INTO users (username, password, is_admin) 
VALUES ('admin', 'admin123', 1);

-- Insert sample client user with plain text password
INSERT INTO users (username, password, is_admin) 
VALUES ('client1', 'client123', 0);

-- Insert sample client data with referral code
INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code) 
VALUES (2, 'John Doe', 'john@example.com', '9876543210', '123 Main St, City', 'ABCDE1234F', 'abc12345');

-- Insert sample ITR records
INSERT INTO itr_records (client_id, itr_type, year, status, filing_date) 
VALUES (1, 'ITR-1', '2022-2023', 'Completed', '2023-07-15');
INSERT INTO itr_records (client_id, itr_type, year, status) 
VALUES (1, 'ITR-1', '2023-2024', 'Pending');

-- Insert sample notifications
INSERT INTO notifications (client_id, message) 
VALUES (1, 'Your ITR for 2022-2023 has been successfully filed.');
INSERT INTO notifications (client_id, message) 
VALUES (1, 'Please submit your Form 16 for the financial year 2023-2024.');

-- Insert sample referrals
INSERT INTO referrals (client_id, referred_name, referred_email, referred_phone, is_reviewed) 
VALUES (1, 'Jane Smith', 'jane@example.com', '8765432109', 0);

-- Insert sample admin notifications
INSERT INTO admin_notifications (message, type, related_id) 
VALUES ('John Doe has referred Jane Smith (jane@example.com)', 'referral', 1);
'''
        with open('schema.sql', 'w') as f:
            f.write(schema_content)
        print("Created schema.sql file")

# Create client templates if they don't exist
def create_client_templates():
    templates_dir = os.path.join(app.template_folder, 'client')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Client login template
    login_path = os.path.join(templates_dir, 'login.html')
    if not os.path.exists(login_path):
        login_content = '''
{% extends 'base.html' %}

{% block title %}Client Login{% endblock %}

{% block content %}
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="card shadow mt-5">
                <div class="card-header bg-success text-white text-center">
                    <h4 class="mb-0">Client Login</h4>
                </div>
                <div class="card-body">
                    <form method="post" class="needs-validation" novalidate>
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="bi bi-person"></i></span>
                                <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" required>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="bi bi-lock"></i></span>
                                <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" required>
                            </div>
                        </div>
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-success">
                                <i class="bi bi-box-arrow-in-right me-2"></i>Login
                            </button>
                        </div>
                    </form>
                    
                    <div class="mt-4 p-2 bg-light border rounded">
                        <p class="small text-muted mb-1">Demo Credentials:</p>
                        <p class="small mb-0">Username: client1</p>
                        <p class="small mb-0">Password: client123</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''
        with open(login_path, 'w') as f:
            f.write(login_content)
    
    # Client dashboard template
    dashboard_path = os.path.join(templates_dir, 'dashboard.html')
    if not os.path.exists(dashboard_path):
        dashboard_content = '''
{% extends 'base.html' %}

{% block title %}Client Dashboard{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-speedometer2 me-2"></i>Welcome, {{ client.full_name }}</h2>
    <div>
        <a href="{{ url_for('client.refer') }}" class="btn btn-outline-primary me-2">
            <i class="bi bi-share me-1"></i>Refer a Friend
        </a>
        <a href="{{ url_for('client.profile') }}" class="btn btn-outline-primary">
            <i class="bi bi-person-circle me-1"></i>View Profile
        </a>
    </div>
</div>

<div class="row">
    <div class="col-md-4">
        <div class="card shadow mb-4">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0"><i class="bi bi-bell me-2"></i>Notifications</h5>
            </div>
            <div class="card-body p-0">
                <div class="list-group list-group-flush">
                    {% for notification in notifications %}
                    <div class="list-group-item list-group-item-action {% if not notification.is_read %}list-group-item-warning{% endif %}">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">{{ notification.message }}</h6>
                            <small>{{ notification.created_at }}</small>
                        </div>
                        {% if not notification.is_read %}
                        <form method="post" action="{{ url_for('client.read_notification', notification_id=notification.id) }}" class="mt-2">
                            <button type="submit" class="btn btn-sm btn-outline-secondary">Mark as Read</button>
                        </form>
                        {% endif %}
                    </div>
                    {% else %}
                    <div class="list-group-item">
                        <p class="text-center mb-0">No notifications</p>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Referral Card -->
        <div class="card shadow mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0"><i class="bi bi-share me-2"></i>Refer & Earn</h5>
            </div>
            <div class="card-body">
                <p>Share your referral link with friends and family:</p>
                <div class="input-group mb-3">
                    <input type="text" class="form-control" id="referralUrl" value="{{ referral_url }}" readonly>
                    <button class="btn btn-outline-primary" type="button" id="copyReferralBtn" onclick="copyReferralUrl()">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <div id="copyMessage" class="text-success d-none">Copied!</div>
                <a href="{{ url_for('client.refer') }}" class="btn btn-primary w-100 mt-2">
                    <i class="bi bi-person-plus me-1"></i>Refer Someone
                </a>
                
                {% if referrals %}
                <hr>
                <h6>Your Referrals ({{ referrals|length }})</h6>
                <div class="list-group list-group-flush">
                    {% for referral in referrals[:3] %}
                    <div class="list-group-item p-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <strong>{{ referral.referred_name }}</strong>
                                <div class="small text-muted">{{ referral.created_at }}</div>
                            </div>
                            <span class="badge bg-{{ 'success' if referral.is_registered else 'warning' }}">
                                {{ 'Registered' if referral.is_registered else 'Pending' }}
                            </span>
                        </div>
                    </div>
                    {% endfor %}
                    {% if referrals|length > 3 %}
                    <a href="{{ url_for('client.refer') }}" class="list-group-item text-center">View all referrals</a>
                    {% endif %}
                </div>
                {% endif %}
            </div>
        </div>
    </div>

    <div class="col-md-8">
        <div class="card shadow">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0"><i class="bi bi-file-earmark-text me-2"></i>Your ITR Records</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>ITR Type</th>
                                <th>Year</th>
                                <th>Status</th>
                                <th>Filing Date</th>
                                <th>Document</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for record in itr_records %}
                            <tr>
                                <td>{{ record.itr_type }}</td>
                                <td>{{ record.year }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if record.status == 'Completed' else 'warning' if record.status == 'In Progress' else 'secondary' }}">
                                        {{ record.status }}
                                    </span>
                                </td>
                                <td>{{ record.filing_date or 'Not filed' }}</td>
                                <td>
                                    {% if record.document_path %}
                                    <a href="{{ record.document_path }}" target="_blank" class="btn btn-sm btn-outline-primary">
                                        <i class="bi bi-file-earmark-arrow-down me-1"></i>Download
                                    </a>
                                    {% else %}
                                    <span class="text-muted">No document</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% else %}
                            <tr>
                                <td colspan="5" class="text-center">No ITR records found</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function copyReferralUrl() {
    var copyText = document.getElementById("referralUrl");
    copyText.select();
    copyText.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(copyText.value);
    
    var copyMessage = document.getElementById("copyMessage");
    copyMessage.classList.remove("d-none");
    
    // Send a request to the server to log the copy action
    fetch("{{ url_for('client.copy_referral_url') }}", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        }
    });
    
    setTimeout(function() {
        copyMessage.classList.add("d-none");
    }, 2000);
}
</script>
{% endblock %}
'''
        with open(dashboard_path, 'w') as f:
            f.write(dashboard_content)
    
    # Client profile template
    profile_path = os.path.join(templates_dir, 'profile.html')
    if not os.path.exists(profile_path):
        profile_content = '''
{% extends 'base.html' %}

{% block title %}Client Profile{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-person-circle me-2"></i>Your Profile</h2>
    <a href="{{ url_for('client.dashboard') }}" class="btn btn-success">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<div class="row">
    <div class="col-md-6 mx-auto">
        <div class="card shadow">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0">Personal Information</h5>
            </div>
            <div class="card-body">
                <div class="text-center mb-4">
                    <div class="avatar-circle mb-3">
                        <span class="initials">{{ client.full_name[0] }}</span>
                    </div>
                    <h3>{{ client.full_name }}</h3>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-4 fw-bold">Email:</div>
                    <div class="col-md-8">{{ client.email }}</div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-4 fw-bold">Phone:</div>
                    <div class="col-md-8">{{ client.phone }}</div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-4 fw-bold">Address:</div>
                    <div class="col-md-8">{{ client.address }}</div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-4 fw-bold">PAN Number:</div>
                    <div class="col-md-8">{{ client.pan_number }}</div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-4 fw-bold">Account Created:</div>
                    <div class="col-md-8">{{ client.created_at }}</div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-4 fw-bold">Referral Code:</div>
                    <div class="col-md-8">{{ client.referral_code }}</div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''
        with open(profile_path, 'w') as f:
            f.write(profile_content)
    
    # Client referral template
    referral_path = os.path.join(templates_dir, 'referral.html')
    if not os.path.exists(referral_path):
        referral_content = '''
{% extends 'base.html' %}

{% block title %}Refer a Friend{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-share me-2"></i>Refer a Friend</h2>
    <a href="{{ url_for('client.dashboard') }}" class="btn btn-success">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card shadow mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">Share Your Referral Link</h5>
            </div>
            <div class="card-body">
                <p>Share this link with your friends and family:</p>
                <div class="input-group mb-3">
                    <input type="text" class="form-control" id="referralUrl" value="{{ referral_url }}" readonly>
                    <button class="btn btn-outline-primary" type="button" id="copyReferralBtn" onclick="copyReferralUrl()">
                        <i class="bi bi-clipboard"></i>
                    </button>
                </div>
                <div id="copyMessage" class="text-success d-none">Copied!</div>
                
                <hr>
                
                <h5>Or Enter Their Details</h5>
                <form method="post" class="needs-validation" novalidate>
                    <div class="mb-3">
                        <label for="referred_name" class="form-label">Full Name</label>
                        <input type="text" class="form-control" id="referred_name" name="referred_name" required>
                    </div>
                    <div class="mb-3">
                        <label for="referred_email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="referred_email" name="referred_email" required>
                    </div>
                    <div class="mb-3">
                        <label for="referred_phone" class="form-label">Phone</label>
                        <input type="tel" class="form-control" id="referred_phone" name="referred_phone" required>
                    </div>
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-send me-1"></i>Send Referral
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card shadow">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">Your Referrals</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Date</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for referral in referrals %}
                            <tr>
                                <td>{{ referral.referred_name }}</td>
                                <td>{{ referral.referred_email }}</td>
                                <td>{{ referral.created_at }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if referral.is_registered else 'warning' }}">
                                        {{ 'Registered' if referral.is_registered else 'Pending' }}
                                    </span>
                                </td>
                            </tr>
                            {% else %}
                            <tr>
                                <td colspan="4" class="text-center">No referrals yet</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function copyReferralUrl() {
    var copyText = document.getElementById("referralUrl");
    copyText.select();
    copyText.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(copyText.value);
    
    var copyMessage = document.getElementById("copyMessage");
    copyMessage.classList.remove("d-none");
    
    // Send a request to the server to log the copy action
    fetch("{{ url_for('client.copy_referral_url') }}", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        }
    });
    
    setTimeout(function() {
        copyMessage.classList.add("d-none");
    }, 2000);
}
</script>
{% endblock %}
'''
        with open(referral_path, 'w') as f:
            f.write(referral_content)

# Create admin templates if they don't exist
def create_admin_templates():
    templates_dir = os.path.join(app.template_folder, 'admin')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Admin dashboard template
    dashboard_path = os.path.join(templates_dir, 'dashboard.html')
    if not os.path.exists(dashboard_path):
        dashboard_content = '''
{% extends 'base.html' %}

{% block title %}Admin Dashboard{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-speedometer2 me-2"></i>Admin Dashboard</h2>
    <div>
        <a href="{{ url_for('admin.referrals') }}" class="btn btn-outline-primary me-2">
            <i class="bi bi-share me-1"></i>Referrals
            {% if unread_referrals_count > 0 %}
            <span class="badge bg-danger">{{ unread_referrals_count }}</span>
            {% endif %}
        </a>
        <a href="{{ url_for('admin.notifications') }}" class="btn btn-outline-primary me-2">
            <i class="bi bi-bell me-1"></i>Notifications
            {% if admin_notifications|length > 0 %}
            <span class="badge bg-danger">{{ admin_notifications|length }}</span>
            {% endif %}
        </a>
        <a href="{{ url_for('admin.client', client_id=1) }}" class="btn btn-outline-primary">
            <i class="bi bi-person-plus me-1"></i>Add Client
        </a>
    </div>
</div>

{% if admin_notifications %}
<div class="alert alert-info alert-dismissible fade show" role="alert">
    <strong>Recent Notifications:</strong>
    <ul class="mb-0">
        {% for notification in admin_notifications[:3] %}
        <li>{{ notification.message }}</li>
        {% endfor %}
    </ul>
    <a href="{{ url_for('admin.notifications') }}" class="alert-link">View all notifications</a>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
{% endif %}

<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0"><i class="bi bi-people me-2"></i>Clients</h5>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead class="table-light">
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>PAN Number</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for client in clients %}
                    <tr>
                        <td>{{ client.id }}</td>
                        <td>{{ client.full_name }}</td>
                        <td>{{ client.email }}</td>
                        <td>{{ client.phone }}</td>
                        <td>{{ client.pan_number }}</td>
                        <td>{{ client.created_at }}</td>
                        <td>
                            <a href="{{ url_for('admin.client_details', client_id=client.id) }}" class="btn btn-sm btn-outline-primary">
                                <i class="bi bi-eye me-1"></i>View
                            </a>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7" class="text-center">No clients found</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
'''
        with open(dashboard_path, 'w') as f:
            f.write(dashboard_content)
    
    # Admin referrals template
    referrals_path = os.path.join(templates_dir, 'referrals.html')
    if not os.path.exists(referrals_path):
        referrals_content = '''
{% extends 'base.html' %}

{% block title %}Referrals{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-share me-2"></i>Referrals</h2>
    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-primary">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">All Referrals</h5>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead class="table-light">
                    <tr>
                        <th>Referrer</th>
                        <th>Referred Person</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for referral in referrals %}
                    <tr class="{% if not referral.is_reviewed %}table-warning{% endif %}">
                        <td>{{ referral.client_name }}</td>
                        <td>{{ referral.referred_name }}</td>
                        <td>{{ referral.referred_email }}</td>
                        <td>{{ referral.referred_phone }}</td>
                        <td>{{ referral.created_at }}</td>
                        <td>
                            <span class="badge bg-{{ 'success' if referral.is_registered else 'warning' }}">
                                {{ 'Registered' if referral.is_registered else 'Pending' }}
                            </span>
                        </td>
                        <td>
                            {% if not referral.is_reviewed %}
                            <form method="post" action="{{ url_for('admin.review_referral', referral_id=referral.id) }}">
                                <button type="submit" class="btn btn-sm btn-outline-success">
                                    <i class="bi bi-check-circle me-1"></i>Mark as Reviewed
                                </button>
                            </form>
                            {% else %}
                            <span class="text-muted">Reviewed</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7" class="text-center">No referrals found</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}
'''
        with open(referrals_path, 'w') as f:
            f.write(referrals_content)
    
    # Admin notifications template
    notifications_path = os.path.join(templates_dir, 'notifications.html')
    if not os.path.exists(notifications_path):
        notifications_content = '''
{% extends 'base.html' %}

{% block title %}Admin Notifications{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-bell me-2"></i>Admin Notifications</h2>
    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-primary">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">All Notifications</h5>
    </div>
    <div class="card-body">
        <div class="list-group">
            {% for notification in notifications %}
            <div class="list-group-item list-group-item-action">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">{{ notification.message }}</h6>
                    <small>{{ notification.created_at }}</small>
                </div>
                <p class="mb-1">
                    <span class="badge bg-{{ 'primary' if notification.type == 'referral' else 'success' if notification.type == 'registration' else 'secondary' }}">
                        {{ notification.type|capitalize }}
                    </span>
                    {% if notification.type == 'referral' %}
                    <a href="{{ url_for('admin.referrals') }}" class="btn btn-sm btn-outline-primary ms-2">
                        <i class="bi bi-eye me-1"></i>View Referrals
                    </a>
                    {% endif %}
                </p>
            </div>
            {% else %}
            <div class="list-group-item">
                <p class="text-center mb-0">No notifications found</p>
            </div>
            {% endfor %}
        </div>
    </div>
</div>
{% endblock %}
'''
        with open(notifications_path, 'w') as f:
            f.write(notifications_content)

# Create register template if it doesn't exist
def create_register_template():
    templates_dir = os.path.join(app.template_folder)
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    register_path = os.path.join(templates_dir, 'register.html')
    if not os.path.exists(register_path):
        register_content = '''
{% extends 'base.html' %}

{% block title %}Register{% endblock %}

{% block content %}
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card shadow mt-4 mb-5">
                <div class="card-header bg-primary text-white text-center">
                    <h4 class="mb-0">Register for ITR Management System</h4>
                    {% if referrer_id %}
                    <p class="mb-0 mt-1">You've been referred by a friend!</p>
                    {% endif %}
                </div>
                <div class="card-body">
                    <form method="post" class="needs-validation" novalidate>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="username" class="form-label">Username</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="bi bi-person"></i></span>
                                    <input type="text" class="form-control" id="username" name="username" required>
                                </div>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="password" class="form-label">Password</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="bi bi-lock"></i></span>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="full_name" class="form-label">Full Name</label>
                                <input type="text" class="form-control" id="full_name" name="full_name" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="phone" class="form-label">Phone</label>
                                <input type="tel" class="form-control" id="phone" name="phone" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="pan_number" class="form-label">PAN Number (Optional)</label>
                                <input type="text" class="form-control" id="pan_number" name="pan_number">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="address" class="form-label">Address (Optional)</label>
                            <textarea class="form-control" id="address" name="address" rows="2"></textarea>
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-person-plus me-2"></i>Register
                            </button>
                        </div>
                    </form>
                    
                    <div class="text-center mt-3">
                        <p>Already have an account? <a href="{{ url_for('client.login') }}">Login here</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'''
        with open(register_path, 'w') as f:
            f.write(register_content)

# Create error templates if they don't exist
def create_error_templates():
    templates_dir = os.path.join(app.template_folder)
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    # 404 template
    not_found_path = os.path.join(templates_dir, '404.html')
    if not os.path.exists(not_found_path):
        not_found_content = '''
{% extends 'base.html' %}

{% block title %}Page Not Found{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-6 text-center">
        <h1 class="display-1">404</h1>
        <h2>Page Not Found</h2>
        <p class="lead">The page you are looking for does not exist.</p>
        <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
    </div>
</div>
{% endblock %}
'''
        with open(not_found_path, 'w') as f:
            f.write(not_found_content)

    # 500 template
    server_error_path = os.path.join(templates_dir, '500.html')
    if not os.path.exists(server_error_path):
        server_error_content = '''
{% extends 'base.html' %}

{% block title %}Server Error{% endblock %}

{% block content %}
<div class="row justify-content-center mt-5">
    <div class="col-md-6 text-center">
        <h1 class="display-1">500</h1>
        <h2>Server Error</h2>
        <p class="lead">Something went wrong on our end. Please try again later.</p>
        <a href="{{ url_for('index') }}" class="btn btn-primary">Go Home</a>
    </div>
</div>
{% endblock %}
'''
        with open(server_error_path, 'w') as f:
            f.write(server_error_content)

# Reset database with plain text passwords for testing
def reset_database():
    """Reset the database with plain text passwords for testing"""
    import os
    if os.path.exists('database.db'):
        os.remove('database.db')
        print("Removed existing database")
    
    # Initialize the database
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()
        print("Database initialized with plain text passwords")

# Create CSS file if it doesn't exist
def create_css_file():
    css_dir = os.path.join(app.static_folder, 'css')
    os.makedirs(css_dir, exist_ok=True)
    
    css_path = os.path.join(css_dir, 'style.css')
    if not os.path.exists(css_path):
        css_content = '''
/* Global Styles */
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f8f9fa;
}

.navbar-brand {
    font-weight: 600;
}

.card {
    border-radius: 0.5rem;
    border: none;
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
}

.card-header {
    border-radius: 0.5rem 0.5rem 0 0 !important;
}

/* Avatar styles */
.avatar-circle {
    width: 80px;
    height: 80px;
    background-color: #28a745;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    margin: 0 auto;
}

.initials {
    font-size: 2rem;
    color: white;
    font-weight: bold;
}

/* Footer */
.footer {
    margin-top: 3rem;
    padding: 1.5rem 0;
    background-color: #f8f9fa;
    border-top: 1px solid #e9ecef;
}

/* Notification styles */
.list-group-item-warning {
    background-color: #fff3cd;
    border-left: 4px solid #ffc107;
}

/* Table styles */
.table-responsive {
    overflow-x: auto;
}

.table th {
    background-color: #f8f9fa;
}

/* Badge styles */
.badge {
    padding: 0.5em 0.75em;
}

/* Referral styles */
.referral-box {
    background-color: #e9f7ef;
    border-left: 4px solid #28a745;
    padding: 1rem;
    margin-bottom: 1rem;
}

.referral-url {
    background-color: #f8f9fa;
    padding: 0.5rem;
    border-radius: 0.25rem;
    font-family: monospace;
}
'''
        with open(css_path, 'w') as f:
            f.write(css_content)
        print(f"Created CSS file at {css_path}")

if __name__ == '__main__':
    # Create necessary files and directories
    create_schema_file()
    create_error_templates()
    create_client_templates()
    create_admin_templates()
    create_register_template()
    create_css_file()
    
    # Check if database exists, if not initialize it
    if not os.path.exists('database.db'):
        init_db()
        print("Database initialized with sample data")
    
    # Uncomment the line below to reset the database with plain text passwords
    # This will delete the existing database and create a new one
    # Comment it out after running once
    reset_database()
    
    # Run the app
    app.run(debug=DEBUG, port=8080)
