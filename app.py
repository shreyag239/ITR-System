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
    return dict(query_db=query_db)

# Add datetime to template context
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

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
        'admin/inactive_clients.html',
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
        # Get all clients (active by default since is_active field might not exist)
        clients = query_db('SELECT * FROM clients ORDER BY created_at DESC')
        if DEBUG:
            print(f"Found {len(clients)} clients")
        
        # Initialize all variables with default values
        total_clients = len(clients) if clients else 0
        total_inactive_clients = 0
        unread_referrals_count = 0
        total_referrals = 0
        admin_notifications_count = 0
        admin_notifications = []
        
        # Try to get statistics with error handling for each query
        try:
            # Check if is_active column exists in clients table
            db = get_db()
            cursor = db.execute("PRAGMA table_info(clients)")
            columns = [column[1] for column in cursor.fetchall()]
            has_is_active = 'is_active' in columns
            
            if has_is_active:
                # Get active clients count
                active_result = query_db('SELECT COUNT(*) as count FROM clients WHERE is_active = 1', one=True)
                total_clients = active_result['count'] if active_result else 0
                
                # Get inactive clients count
                inactive_result = query_db('SELECT COUNT(*) as count FROM clients WHERE is_active = 0', one=True)
                total_inactive_clients = inactive_result['count'] if inactive_result else 0
                
                # Filter clients to show only active ones
                clients = query_db('SELECT * FROM clients WHERE is_active = 1 ORDER BY created_at DESC')
            else:
                # If is_active column doesn't exist, all clients are considered active
                total_clients = len(clients)
                total_inactive_clients = 0
                print("Warning: is_active column not found in clients table")
        except Exception as e:
            print(f"Error checking clients status: {e}")
        
        try:
            # Get unread referrals count
            unread_result = query_db('SELECT COUNT(*) as count FROM referrals WHERE is_reviewed = 0', one=True)
            unread_referrals_count = unread_result['count'] if unread_result else 0
        except Exception as e:
            print(f"Error getting unread referrals: {e}")
        
        try:
            # Get total referrals count
            total_result = query_db('SELECT COUNT(*) as count FROM referrals', one=True)
            total_referrals = total_result['count'] if total_result else 0
        except Exception as e:
            print(f"Error getting total referrals: {e}")
        
        try:
            # Get admin notifications
            admin_notifications = query_db('SELECT * FROM admin_notifications WHERE is_read = 0 ORDER BY created_at DESC')
            admin_notifications_count = len(admin_notifications) if admin_notifications else 0
        except Exception as e:
            print(f"Error getting admin notifications: {e}")
            admin_notifications = []
        
        # Debug print to verify all values are set
        print(f"Dashboard stats - Active: {total_clients}, Inactive: {total_inactive_clients}, "
              f"Unread Referrals: {unread_referrals_count}, Total Referrals: {total_referrals}, "
              f"Admin Notifications: {admin_notifications_count}")
        
        return render_template('admin/dashboard.html', 
                              clients=clients or [], 
                              total_clients=total_clients,
                              total_inactive_clients=total_inactive_clients,
                              unread_referrals_count=unread_referrals_count,
                              total_referrals=total_referrals,
                              admin_notifications_count=admin_notifications_count,
                              admin_notifications=admin_notifications or [])
    except Exception as e:
        print(f"Dashboard error: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        flash(f"Error loading dashboard: {str(e)}", 'error')
        return redirect(url_for('admin.login'))

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
        
        # Check if is_active column exists
        db = get_db()
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_active = 'is_active' in columns
        
        if has_is_active:
            client_id = insert_db(
                'INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [user_id, full_name, email, phone, address, pan_number, referral_code, 1]
            )
        else:
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

@admin_bp.route('/client/<int:client_id>/delete', methods=['POST'])
@admin_required
def delete_client(client_id):
    # Get the client to be deleted
    client = query_db('SELECT * FROM clients WHERE id = ?', [client_id], one=True)
    
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Begin transaction to ensure all related data is deleted
    db = get_db()
    try:
        # Delete all ITR records for this client
        db.execute('DELETE FROM itr_records WHERE client_id = ?', [client_id])
        
        # Delete all notifications for this client
        db.execute('DELETE FROM notifications WHERE client_id = ?', [client_id])
        
        # Delete all referrals made by this client
        db.execute('DELETE FROM referrals WHERE client_id = ?', [client_id])
        
        # Update any referrals where this client was referred (set referred_client_id to NULL)
        db.execute('UPDATE referrals SET referred_client_id = NULL WHERE referred_client_id = ?', [client_id])
        
        # Get user_id to delete the user account if it exists
        user_id = client['user_id']
        
        # Delete the client
        db.execute('DELETE FROM clients WHERE id = ?', [client_id])
        
        # Delete the user account if it exists and is not an admin
        if user_id:
            # Check if user is not an admin before deleting
            user = query_db('SELECT * FROM users WHERE id = ? AND is_admin = 0', [user_id], one=True)
            if user:
                db.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', [user_id])
        
        # Commit all changes
        db.commit()
        
        flash(f'Client {client["full_name"]} has been deleted successfully.', 'success')
    except Exception as e:
        # Rollback in case of error
        db.rollback()
        flash(f'Error deleting client: {str(e)}', 'error')
    
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/referrals')
@admin_required
def referrals():
    try:
        conn = get_db()
        
        # Get search and filter parameters
        search = request.args.get('search', '')
        status_filter = request.args.get('status', '')
        
        # Initialize variables
        referrals_data = []
        stats = {
            'total': 0,
            'pending': 0,
            'contacted': 0,
            'converted': 0,
            'rejected': 0,
            'conversion_rate': 0
        }
        
        # Check if referrals table exists
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='referrals'").fetchone()
        if not table_exists:
            print("Referrals table does not exist!")
            flash("Referrals feature is not available. Database needs to be initialized.", "error")
            return render_template('admin/referrals.html', 
                                referrals=[], 
                                stats=stats,
                                search=search,
                                status_filter=status_filter)
        
        # Check table structure
        cursor = conn.execute("PRAGMA table_info(referrals)")
        columns = [column[1] for column in cursor.fetchall()]
        has_status = 'status' in columns
        
        # Base query with JOIN to get client names
        query = '''
            SELECT r.*, c.full_name as client_name 
            FROM referrals r 
            LEFT JOIN clients c ON r.client_id = c.id 
            WHERE 1=1
        '''
        params = []
        
        # Add search filter
        if search:
            query += ' AND (r.referred_name LIKE ? OR r.referred_email LIKE ? OR c.full_name LIKE ?)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param])
        
        # Add status filter
        if has_status and status_filter:
            query += ' AND r.status = ?'
            params.append(status_filter)
        
        query += ' ORDER BY r.created_at DESC'
        
        print(f"Executing query: {query} with params: {params}")
        referrals_data = conn.execute(query, params).fetchall()
        print(f"Found {len(referrals_data)} referrals")
        
        # Get statistics
        stats['total'] = conn.execute('SELECT COUNT(*) as count FROM referrals').fetchone()['count']
        
        if has_status:
            stats['pending'] = conn.execute('SELECT COUNT(*) as count FROM referrals WHERE status = "Pending"').fetchone()['count']
            stats['contacted'] = conn.execute('SELECT COUNT(*) as count FROM referrals WHERE status = "Contacted"').fetchone()['count']
            stats['converted'] = conn.execute('SELECT COUNT(*) as count FROM referrals WHERE status = "Converted"').fetchone()['count']
            stats['rejected'] = conn.execute('SELECT COUNT(*) as count FROM referrals WHERE status = "Rejected"').fetchone()['count']
            
            # Calculate conversion rate
            if stats['total'] > 0:
                stats['conversion_rate'] = round((stats['converted'] / stats['total']) * 100, 1)
        
        return render_template('admin/referrals.html', 
                            referrals=referrals_data, 
                            stats=stats,
                            search=search,
                            status_filter=status_filter)
                            
    except Exception as e:
        print(f"Error in referrals route: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        flash(f"Error loading referrals: {str(e)}", "error")
        return render_template('admin/referrals.html', 
                            referrals=[], 
                            stats={'total': 0, 'pending': 0, 'contacted': 0, 'converted': 0, 'rejected': 0, 'conversion_rate': 0},
                            search='',
                            status_filter='')

@admin_bp.route('/referrals/<int:referral_id>/update_status', methods=['POST'])
@admin_required
def update_referral_status(referral_id):
    new_status = request.form.get('status')
    
    if not new_status:
        flash('Invalid referral data!', 'error')
        return redirect(url_for('admin.referrals'))
    
    conn = get_db()
    
    # Check if status and is_read columns exist
    try:
        cursor = conn.execute("PRAGMA table_info(referrals)")
        columns = [column[1] for column in cursor.fetchall()]
        has_status = 'status' in columns
        has_is_read = 'is_read' in columns
        
        if has_status and has_is_read:
            conn.execute('''
                UPDATE referrals 
                SET status = ?, is_read = 1 
                WHERE id = ?
            ''', (new_status, referral_id))
        elif has_status:
            conn.execute('''
                UPDATE referrals 
                SET status = ? 
                WHERE id = ?
            ''', (new_status, referral_id))
        else:
            flash('Status update not supported in current database schema', 'error')
            return redirect(url_for('admin.referrals'))
        
        conn.commit()
        flash(f'Referral status updated to {new_status}!', 'success')
    except Exception as e:
        print(f"Error updating referral status: {e}")
        flash('Error updating referral status', 'error')
    
    return redirect(url_for('admin.referrals'))

@admin_bp.route('/referrals/<int:referral_id>/review', methods=['POST'])
@admin_required
def review_referral(referral_id):
    conn = get_db()
    try:
        # Check if is_reviewed column exists
        cursor = conn.execute("PRAGMA table_info(referrals)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_reviewed = 'is_reviewed' in columns
        
        if has_is_reviewed:
            conn.execute('UPDATE referrals SET is_reviewed = 1 WHERE id = ?', (referral_id,))
            conn.commit()
            flash('Referral marked as reviewed!', 'success')
        else:
            flash('Review feature not supported in current database schema', 'error')
    except Exception as e:
        print(f"Error reviewing referral: {e}")
        flash('Error reviewing referral', 'error')
    
    return redirect(url_for('admin.referrals'))

@admin_bp.route('/referrals/mark_read/<int:referral_id>', methods=['POST'])
@admin_required
def mark_referral_read(referral_id):
    conn = get_db()
    try:
        # Check if is_read column exists
        cursor = conn.execute("PRAGMA table_info(referrals)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_read = 'is_read' in columns
        
        if has_is_read:
            conn.execute('UPDATE referrals SET is_read = 1 WHERE id = ?', (referral_id,))
            conn.commit()
        else:
            # Use is_reviewed if is_read doesn't exist
            conn.execute('UPDATE referrals SET is_reviewed = 1 WHERE id = ?', (referral_id,))
            conn.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error marking referral as read: {e}")
        return jsonify({'success': False, 'error': str(e)})

@admin_bp.route('/referrals/bulk_action', methods=['POST'])
@admin_required
def bulk_referral_action():
    action = request.form.get('action')
    referral_ids = request.form.getlist('referral_ids')
    
    if not action or not referral_ids:
        flash('Please select referrals and an action!', 'error')
        return redirect(url_for('admin.referrals'))
    
    conn = get_db()
    
    try:
        # Check available columns
        cursor = conn.execute("PRAGMA table_info(referrals)")
        columns = [column[1] for column in cursor.fetchall()]
        has_status = 'status' in columns
        has_is_read = 'is_read' in columns
        
        if action == 'mark_read':
            placeholders = ','.join(['?' for _ in referral_ids])
            if has_is_read:
                conn.execute(f'UPDATE referrals SET is_read = 1 WHERE id IN ({placeholders})', referral_ids)
            else:
                conn.execute(f'UPDATE referrals SET is_reviewed = 1 WHERE id IN ({placeholders})', referral_ids)
            flash(f'{len(referral_ids)} referrals marked as read!', 'success')
        
        elif action in ['Pending', 'Contacted', 'Converted', 'Rejected'] and has_status:
            placeholders = ','.join(['?' for _ in referral_ids])
            if has_is_read:
                conn.execute(f'UPDATE referrals SET status = ?, is_read = 1 WHERE id IN ({placeholders})', 
                            [action] + referral_ids)
            else:
                conn.execute(f'UPDATE referrals SET status = ? WHERE id IN ({placeholders})', 
                            [action] + referral_ids)
            flash(f'{len(referral_ids)} referrals updated to {action}!', 'success')
        else:
            flash('Action not supported in current database schema', 'error')
            return redirect(url_for('admin.referrals'))
        
        conn.commit()
    except Exception as e:
        print(f"Error in bulk action: {e}")
        flash('Error performing bulk action', 'error')
    
    return redirect(url_for('admin.referrals'))

@admin_bp.route('/inactive_clients')
@admin_required
def inactive_clients():
    try:
        # Check if is_active column exists
        db = get_db()
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_active = 'is_active' in columns
        
        if has_is_active:
            clients = db.execute('''
                SELECT * FROM clients 
                WHERE is_active = 0 
                ORDER BY deactivated_at DESC
            ''').fetchall()
        else:
            # If no is_active column, return empty list
            clients = []
            flash('Inactive clients feature requires database schema update', 'warning')
        
        return render_template('admin/inactive_clients.html', clients=clients)
    except Exception as e:
        print(f"Error loading inactive clients: {e}")
        flash('Error loading inactive clients', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/deactivate_client/<int:client_id>', methods=['POST'])
@admin_required
def deactivate_client(client_id):
    try:
        db = get_db()
        
        # Check if is_active column exists
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_active = 'is_active' in columns
        has_deactivated_at = 'deactivated_at' in columns
        
        if not has_is_active:
            # Add the column if it doesn't exist
            db.execute('ALTER TABLE clients ADD COLUMN is_active INTEGER DEFAULT 1')
            db.commit()
            has_is_active = True
            print("Added is_active column to clients table")
        
        if not has_deactivated_at:
            # Add the column if it doesn't exist
            db.execute('ALTER TABLE clients ADD COLUMN deactivated_at TIMESTAMP NULL')
            db.commit()
            has_deactivated_at = True
            print("Added deactivated_at column to clients table")
        
        # Now perform the deactivation
        if has_deactivated_at:
            db.execute('''
                UPDATE clients 
                SET is_active = 0, deactivated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (client_id,))
        else:
            db.execute('''
                UPDATE clients 
                SET is_active = 0 
                WHERE id = ?
            ''', (client_id,))
        
        db.commit()
        flash('Client has been deactivated successfully!', 'success')
        
    except Exception as e:
        print(f"Error deactivating client: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        flash(f'Error deactivating client: {str(e)}', 'error')
    
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/reactivate_client/<int:client_id>', methods=['POST'])
@admin_required
def reactivate_client(client_id):
    try:
        db = get_db()
        
        # Check if is_active column exists
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_active = 'is_active' in columns
        has_deactivated_at = 'deactivated_at' in columns
        
        if not has_is_active:
            flash('Database schema needs to be updated. Please contact administrator.', 'error')
            return redirect(url_for('admin.inactive_clients'))
        
        # Perform the reactivation
        if has_deactivated_at:
            db.execute('''
                UPDATE clients 
                SET is_active = 1, deactivated_at = NULL 
                WHERE id = ?
            ''', (client_id,))
        else:
            db.execute('''
                UPDATE clients 
                SET is_active = 1 
                WHERE id = ?
            ''', (client_id,))
        
        db.commit()
        flash('Client has been reactivated successfully!', 'success')
        
    except Exception as e:
        print(f"Error reactivating client: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()
        flash(f'Error reactivating client: {str(e)}', 'error')
    
    return redirect(url_for('admin.inactive_clients'))

@admin_bp.route('/delete_client_permanently/<int:client_id>', methods=['POST'])
@admin_required
def delete_client_permanently(client_id):
    try:
        db = get_db()
        
        # Check if is_active column exists
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_active = 'is_active' in columns
        
        if has_is_active:
            # Check if client is inactive
            client = db.execute('SELECT is_active FROM clients WHERE id = ?', (client_id,)).fetchone()
            
            if not client or client['is_active'] == 1:
                flash('Can only permanently delete inactive clients!', 'error')
                return redirect(url_for('admin.inactive_clients'))
        
        # Delete all related data
        db.execute('DELETE FROM notifications WHERE client_id = ?', (client_id,))
        db.execute('DELETE FROM itr_records WHERE client_id = ?', (client_id,))
        db.execute('DELETE FROM referrals WHERE client_id = ?', (client_id,))
        db.execute('DELETE FROM clients WHERE id = ?', (client_id,))
        
        db.commit()
        flash('Client and all associated data have been permanently deleted!', 'success')
    except Exception as e:
        print(f"Error permanently deleting client: {e}")
        flash('Error permanently deleting client', 'error')
    
    return redirect(url_for('admin.inactive_clients'))

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
        
        # Check if is_active column exists
        db = get_db()
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        has_is_active = 'is_active' in columns
        
        # Create client profile
        if has_is_active:
            client_id = insert_db(
                'INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [user_id, full_name, email, phone, address, pan_number, referral_code, 1]
            )
        else:
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

@app.route('/public-refer', methods=['GET', 'POST'])
def public_refer():
    success = False
    
    if request.method == 'POST':
        # Get form data
        referrer_name = request.form.get('referrer_name')
        referrer_email = request.form.get('referrer_email')
        referrer_phone = request.form.get('referrer_phone')
        referred_name = request.form.get('referred_name')
        referred_email = request.form.get('referred_email')
        referred_phone = request.form.get('referred_phone')
        message = request.form.get('message', '')
        
        try:
            # Create a temporary referrer record or find existing client with same email
            client = query_db('SELECT * FROM clients WHERE email = ?', [referrer_email], one=True)
            client_id = None
            
            if client:
                # Use existing client
                client_id = client['id']
            else:
                # Create a temporary client entry for the referrer
                user_id = insert_db(
                    'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                    [referrer_email, str(uuid.uuid4()), 0]  # Generate random password
                )
                
                if user_id:
                    # Generate referral code
                    referral_code = str(uuid.uuid4())[:8]
                    
                    # Check if is_active column exists
                    db = get_db()
                    cursor = db.execute("PRAGMA table_info(clients)")
                    columns = [column[1] for column in cursor.fetchall()]
                    has_is_active = 'is_active' in columns
                    
                    # Create client profile
                    if has_is_active:
                        client_id = insert_db(
                            'INSERT INTO clients (user_id, full_name, email, phone, referral_code, is_active) VALUES (?, ?, ?, ?, ?, ?)',
                            [user_id, referrer_name, referrer_email, referrer_phone, referral_code, 1]
                        )
                    else:
                        client_id = insert_db(
                            'INSERT INTO clients (user_id, full_name, email, phone, referral_code) VALUES (?, ?, ?, ?, ?)',
                            [user_id, referrer_name, referrer_email, referrer_phone, referral_code]
                        )
            
            if client_id:
                # Add referral to database
                referral_id = insert_db(
                    '''INSERT INTO referrals 
                       (client_id, referred_name, referred_email, referred_phone) 
                       VALUES (?, ?, ?, ?)''',
                    [client_id, referred_name, referred_email, referred_phone]
                )
                
                if referral_id:
                    # Add admin notification
                    insert_db(
                        '''INSERT INTO admin_notifications 
                           (message, type, related_id) 
                           VALUES (?, ?, ?)''',
                        [f"Public referral: {referrer_name} ({referrer_email}) has referred {referred_name} ({referred_email})", 
                         'referral', 
                         referral_id]
                    )
                    
                    success = True
                    flash('Thank you for your referral! We will contact them soon.', 'success')
                else:
                    flash('Error adding referral. Please try again.', 'error')
            else:
                flash('Error processing your information. Please try again.', 'error')
                
        except Exception as e:
            print(f"Error in public referral: {str(e)}")
            if DEBUG:
                import traceback
                traceback.print_exc()
            flash('An error occurred. Please try again later.', 'error')
    
    return render_template('public_refer.html', success=success)

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
    is_active INTEGER DEFAULT 1,
    deactivated_at TIMESTAMP NULL,
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
    status TEXT DEFAULT 'Pending',
    is_read INTEGER DEFAULT 0,
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
INSERT INTO clients (user_id, full_name, email, phone, address, pan_number, referral_code, is_active) 
VALUES (2, 'John Doe', 'john@example.com', '9876543210', '123 Main St, City', 'ABCDE1234F', 'abc12345', 1);

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
INSERT INTO referrals (client_id, referred_name, referred_email, referred_phone, status, is_reviewed) 
VALUES (1, 'Jane Smith', 'jane@example.com', '8765432109', 'Pending', 0);

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

# Continue with the rest of the template creation functions...
def create_admin_templates():
    templates_dir = os.path.join(app.template_folder, 'admin')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Admin dashboard template with fixed variables
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
            {% if admin_notifications_count > 0 %}
            <span class="badge bg-danger">{{ admin_notifications_count }}</span>
            {% endif %}
        </a>
        <a href="{{ url_for('admin.add_new_client') }}" class="btn btn-outline-primary me-2">
            <i class="bi bi-person-plus me-1"></i>Add Client
        </a>
        <a href="{{ url_for('admin.inactive_clients') }}" class="btn btn-outline-secondary">
            <i class="bi bi-person-x me-1"></i>Inactive Clients
            {% if total_inactive_clients > 0 %}
            <span class="badge bg-warning">{{ total_inactive_clients }}</span>
            {% endif %}
        </a>
    </div>
</div>

<!-- Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ total_clients }}</h4>
                        <p class="mb-0">Active Clients</p>
                    </div>
                    <div class="align-self-center">
                        <i class="bi bi-people fs-1"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ total_inactive_clients }}</h4>
                        <p class="mb-0">Inactive Clients</p>
                    </div>
                    <div class="align-self-center">
                        <i class="bi bi-person-x fs-1"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ total_referrals }}</h4>
                        <p class="mb-0">Total Referrals</p>
                    </div>
                    <div class="align-self-center">
                        <i class="bi bi-share fs-1"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ unread_referrals_count }}</h4>
                        <p class="mb-0">Unread Referrals</p>
                    </div>
                    <div class="align-self-center">
                        <i class="bi bi-bell fs-1"></i>
                    </div>
                </div>
            </div>
        </div>
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
        <h5 class="mb-0"><i class="bi bi-people me-2"></i>Active Clients</h5>
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
                            <form method="post" action="{{ url_for('admin.deactivate_client', client_id=client.id) }}" class="d-inline">
                                <button type="submit" class="btn btn-sm btn-outline-warning" onclick="return confirm('Are you sure you want to deactivate this client?')">
                                    <i class="bi bi-person-x me-1"></i>Deactivate
                                </button>
                            </form>
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

{% block title %}Referrals Management{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-share me-2"></i>Referrals Management</h2>
    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-primary">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<!-- Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body text-center">
                <h3>{{ stats.total }}</h3>
                <p class="mb-0">Total Referrals</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body text-center">
                <h3>{{ stats.pending }}</h3>
                <p class="mb-0">Pending</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body text-center">
                <h3>{{ stats.contacted }}</h3>
                <p class="mb-0">Contacted</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body text-center">
                <h3>{{ stats.converted }}</h3>
                <p class="mb-0">Converted</p>
            </div>
        </div>
    </div>
</div>

<!-- Search and Filter -->
<div class="card mb-4">
    <div class="card-body">
        <form method="get" class="row g-3">
            <div class="col-md-6">
                <label for="search" class="form-label">Search</label>
                <input type="text" class="form-control" id="search" name="search" 
                       value="{{ search }}" placeholder="Search by name, email, or referrer...">
            </div>
            <div class="col-md-4">
                <label for="status" class="form-label">Status Filter</label>
                <select class="form-select" id="status" name="status">
                    <option value="">All Statuses</option>
                    <option value="Pending" {{ 'selected' if status_filter == 'Pending' }}>Pending</option>
                    <option value="Contacted" {{ 'selected' if status_filter == 'Contacted' }}>Contacted</option>
                    <option value="Converted" {{ 'selected' if status_filter == 'Converted' }}>Converted</option>
                    <option value="Rejected" {{ 'selected' if status_filter == 'Rejected' }}>Rejected</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Bulk Actions -->
<div class="card mb-4">
    <div class="card-body">
        <form method="post" action="{{ url_for('admin.bulk_referral_action') }}" id="bulkForm">
            <div class="row g-3 align-items-end">
                <div class="col-md-4">
                    <label for="bulkAction" class="form-label">Bulk Action</label>
                    <select class="form-select" id="bulkAction" name="action" required>
                        <option value="">Select Action</option>
                        <option value="mark_read">Mark as Read</option>
                        <option value="Pending">Set Status: Pending</option>
                        <option value="Contacted">Set Status: Contacted</option>
                        <option value="Converted">Set Status: Converted</option>
                        <option value="Rejected">Set Status: Rejected</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-warning" onclick="return confirm('Apply action to selected referrals?')">
                        <i class="bi bi-lightning me-1"></i>Apply to Selected
                    </button>
                </div>
                <div class="col-md-4 text-end">
                    <button type="button" class="btn btn-outline-secondary" onclick="selectAll()">Select All</button>
                    <button type="button" class="btn btn-outline-secondary" onclick="selectNone()">Select None</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Referrals Table -->
<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">All Referrals ({{ referrals|length }})</h5>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th width="50">
                            <input type="checkbox" id="selectAllCheckbox" onchange="toggleAll()">
                        </th>
                        <th>Referrer</th>
                        <th>Referred Person</th>
                        <th>Contact Info</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for referral in referrals %}
                    <tr class="{% if not referral.is_reviewed %}table-warning{% endif %}">
                        <td>
                            <input type="checkbox" name="referral_ids" value="{{ referral.id }}" 
                                   form="bulkForm" class="referral-checkbox">
                        </td>
                        <td>
                            <strong>{{ referral.client_name or 'Unknown' }}</strong>
                        </td>
                        <td>
                            <div>
                                <strong>{{ referral.referred_name }}</strong>
                                {% if referral.referred_client_id %}
                                <span class="badge bg-success ms-1">Registered</span>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <div class="small">
                                <div><i class="bi bi-envelope me-1"></i>{{ referral.referred_email }}</div>
                                {% if referral.referred_phone %}
                                <div><i class="bi bi-telephone me-1"></i>{{ referral.referred_phone }}</div>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <small>{{ referral.created_at }}</small>
                        </td>
                        <td>
                            {% if referral.status %}
                            <span class="badge bg-{{ 'success' if referral.status == 'Converted' else 'primary' if referral.status == 'Contacted' else 'warning' if referral.status == 'Pending' else 'danger' }}">
                                {{ referral.status }}
                            </span>
                            {% else %}
                            <span class="badge bg-secondary">No Status</span>
                            {% endif %}
                            
                            {% if not referral.is_read and not referral.is_reviewed %}
                            <span class="badge bg-danger">Unread</span>
                            {% endif %}
                        </td>
                        <td>
                            <div class="btn-group" role="group">
                                <!-- Status Update -->
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-primary dropdown-toggle" type="button" 
                                            data-bs-toggle="dropdown" aria-expanded="false">
                                        Status
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Pending">
                                                <button type="submit" class="dropdown-item">Pending</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Contacted">
                                                <button type="submit" class="dropdown-item">Contacted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Converted">
                                                <button type="submit" class="dropdown-item">Converted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Rejected">
                                                <button type="submit" class="dropdown-item">Rejected</button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>
                                
                                <!-- Mark as Read -->
                                {% if not referral.is_read and not referral.is_reviewed %}
                                <button type="button" class="btn btn-sm btn-outline-success" 
                                        onclick="markAsRead({{ referral.id }})">
                                    <i class="bi bi-check-circle me-1"></i>Read
                                </button>
                                {% endif %}
                                
                                <!-- Mark as Reviewed -->
                                {% if not referral.is_reviewed %}
                                <form method="post" action="{{ url_for('admin.review_referral', referral_id=referral.id) }}" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-info">
                                        <i class="bi bi-eye-check me-1"></i>Review
                                    </button>
                                </form>
                                {% endif %}
                            </div>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7" class="text-center py-4">
                            <div class="text-muted">
                                <i class="bi bi-inbox fs-1"></i>
                                <p class="mt-2">No referrals found</p>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
function markAsRead(referralId) {
    fetch(`{{ url_for('admin.mark_referral_read', referral_id=0) }}`.replace('0', referralId), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Error marking referral as read');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error marking referral as read');
    });
}

function toggleAll() {
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    
    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
}

function selectAll() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    
    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
    });
    selectAllCheckbox.checked = true;
}

function selectNone() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    
    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
    selectAllCheckbox.checked = false;
}
</script>
{% endblock %}
'''
        with open(referrals_path, 'w') as f:
            f.write(referrals_content)

# Reset database with updated schema
def reset_database():
    """Reset the database with updated schema including is_active field"""
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
        print("Database initialized with updated schema including is_active field")

def migrate_database():
    """Migrate existing database to add missing columns"""
    try:
        db = get_db()
        
        # Check if is_active column exists in clients table
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_active' not in columns:
            print("Adding is_active column to clients table...")
            db.execute('ALTER TABLE clients ADD COLUMN is_active INTEGER DEFAULT 1')
            db.commit()
            print("Added is_active column successfully")
        
        if 'deactivated_at' not in columns:
            print("Adding deactivated_at column to clients table...")
            db.execute('ALTER TABLE clients ADD COLUMN deactivated_at TIMESTAMP NULL')
            db.commit()
            print("Added deactivated_at column successfully")
            
    except Exception as e:
        print(f"Error during database migration: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()

def create_base_templates():
    templates_dir = app.template_folder
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Base template
    base_path = os.path.join(templates_dir, 'base.html')
    if not os.path.exists(base_path):
        base_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}ITR Management System{% endblock %}</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    
    <style>
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
        .footer {
            margin-top: 3rem;
            padding: 1.5rem 0;
            background-color: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="bi bi-calculator me-2"></i>ITR Management System
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    {% if session.user_id %}
                        {% if session.is_admin %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('admin.dashboard') }}">
                                <i class="bi bi-speedometer2 me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('admin.referrals') }}">
                                <i class="bi bi-share me-1"></i>Referrals
                            </a>
                        </li>
                        {% else %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('client.dashboard') }}">
                                <i class="bi bi-speedometer2 me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('client.refer') }}">
                                <i class="bi bi-share me-1"></i>Refer Friend
                            </a>
                        </li>
                        {% endif %}
                    {% endif %}
                </ul>
                
                <ul class="navbar-nav">
                    {% if session.user_id %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle me-1"></i>{{ session.username }}
                        </a>
                        <ul class="dropdown-menu">
                            {% if session.is_admin %}
                            <li><a class="dropdown-item" href="{{ url_for('admin.logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Logout
                            </a></li>
                            {% else %}
                            <li><a class="dropdown-item" href="{{ url_for('client.profile') }}">
                                <i class="bi bi-person me-1"></i>Profile
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('client.logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Logout
                            </a></li>
                            {% endif %}
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('admin.login') }}">
                            <i class="bi bi-shield-lock me-1"></i>Admin Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('client.login') }}">
                            <i class="bi bi-person me-1"></i>Client Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('register') }}">
                            <i class="bi bi-person-plus me-1"></i>Register
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ 'danger' if category == 'error' else 'success' if category == 'success' else 'info' if category == 'info' else 'warning' }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <!-- Main Content -->
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p class="text-muted">&copy; 2024 ITR Management System. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-end">
                    <p class="text-muted">Built with Flask & Bootstrap</p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''
        with open(base_path, 'w') as f:
            f.write(base_content)
    
    # Index template
    index_path = os.path.join(templates_dir, 'index.html')
    if not os.path.exists(index_path):
        index_content = '''
{% extends 'base.html' %}

{% block title %}Home - ITR Management System{% endblock %}

{% block content %}
<div class="row">
    <div class="col-lg-8 mx-auto text-center">
        <h1 class="display-4 mb-4">Welcome to ITR Management System</h1>
        <p class="lead mb-5">Streamline your income tax return filing process with our comprehensive management system.</p>
        
        <div class="row">
            <div
'''
        with open(index_path, 'w') as f:
            f.write(index_content)

def create_referrals_template():
    templates_dir = os.path.join(app.template_folder, 'admin')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    referrals_path = os.path.join(templates_dir, 'referrals.html')
    if not os.path.exists(referrals_path):
        referrals_content = '''
{% extends 'base.html' %}

{% block title %}Referrals Management{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-share me-2"></i>Referrals Management</h2>
    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-primary">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<!-- Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body text-center">
                <h3>{{ stats.total }}</h3>
                <p class="mb-0">Total Referrals</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body text-center">
                <h3>{{ stats.pending }}</h3>
                <p class="mb-0">Pending</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body text-center">
                <h3>{{ stats.contacted }}</h3>
                <p class="mb-0">Contacted</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body text-center">
                <h3>{{ stats.converted }}</h3>
                <p class="mb-0">Converted</p>
            </div>
        </div>
    </div>
</div>

<!-- Search and Filter -->
<div class="card mb-4">
    <div class="card-body">
        <form method="get" class="row g-3">
            <div class="col-md-6">
                <label for="search" class="form-label">Search</label>
                <input type="text" class="form-control" id="search" name="search"
                       value="{{ search }}" placeholder="Search by name, email, or referrer...">
            </div>
            <div class="col-md-4">
                <label for="status" class="form-label">Status Filter</label>
                <select class="form-select" id="status" name="status">
                    <option value="">All Statuses</option>
                    <option value="Pending" {{ 'selected' if status_filter == 'Pending' }}>Pending</option>
                    <option value="Contacted" {{ 'selected' if status_filter == 'Contacted' }}>Contacted</option>
                    <option value="Converted" {{ 'selected' if status_filter == 'Converted' }}>Converted</option>
                    <option value="Rejected" {{ 'selected' if status_filter == 'Rejected' }}>Rejected</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Bulk Actions -->
<div class="card mb-4">
    <div class="card-body">
        <form method="post" action="{{ url_for('admin.bulk_referral_action') }}" id="bulkForm">
            <div class="row g-3 align-items-end">
                <div class="col-md-4">
                    <label for="bulkAction" class="form-label">Bulk Action</label>
                    <select class="form-select" id="bulkAction" name="action" required>
                        <option value="">Select Action</option>
                        <option value="mark_read">Mark as Read</option>
                        <option value="Pending">Set Status: Pending</option>
                        <option value="Contacted">Set Status: Contacted</option>
                        <option value="Converted">Set Status: Converted</option>
                        <option value="Rejected">Set Status: Rejected</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-warning" onclick="return confirm('Apply action to selected referrals?')">
                        <i class="bi bi-lightning me-1"></i>Apply to Selected
                    </button>
                </div>
                <div class="col-md-4 text-end">
                    <button type="button" class="btn btn-outline-secondary" onclick="selectAll()">Select All</button>
                    <button type="button" class="btn btn-outline-secondary" onclick="selectNone()">Select None</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Referrals Table -->
<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">All Referrals ({{ referrals|length }})</h5>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th width="50">
                            <input type="checkbox" id="selectAllCheckbox" onchange="toggleAll()">
                        </th>
                        <th>Referrer</th>
                        <th>Referred Person</th>
                        <th>Contact Info</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for referral in referrals %}
                    <tr class="{% if not referral.is_reviewed %}table-warning{% endif %}">
                        <td>
                            <input type="checkbox" name="referral_ids" value="{{ referral.id }}"
                                   form="bulkForm" class="referral-checkbox">
                        </td>
                        <td>
                            <strong>{{ referral.client_name or 'Unknown' }}</strong>
                        </td>
                        <td>
                            <div>
                                <strong>{{ referral.referred_name }}</strong>
                                {% if referral.referred_client_id %}
                                <span class="badge bg-success ms-1">Registered</span>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <div class="small">
                                <div><i class="bi bi-envelope me-1"></i>{{ referral.referred_email }}</div>
                                {% if referral.referred_phone %}
                                <div><i class="bi bi-telephone me-1"></i>{{ referral.referred_phone }}</div>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <small>{{ referral.created_at }}</small>
                        </td>
                        <td>
                            {% if referral.status %}
                            <span class="badge bg-{{ 'success' if referral.status == 'Converted' else 'primary' if referral.status == 'Contacted' else 'warning' if referral.status == 'Pending' else 'danger' }}">
                                {{ referral.status }}
                            </span>
                            {% else %}
                            <span class="badge bg-secondary">No Status</span>
                            {% endif %}

                            {% if not referral.is_read and not referral.is_reviewed %}
                            <span class="badge bg-danger">Unread</span>
                            {% endif %}
                        </td>
                        <td>
                            <div class="btn-group" role="group">
                                <!-- Status Update -->
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-primary dropdown-toggle" type="button"
                                            data-bs-toggle="dropdown" aria-expanded="false">
                                        Status
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Pending">
                                                <button type="submit" class="dropdown-item">Pending</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Contacted">
                                                <button type="submit" class="dropdown-item">Contacted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Converted">
                                                <button type="submit" class="dropdown-item">Converted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Rejected">
                                                <button type="submit" class="dropdown-item">Rejected</button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>

                                <!-- Mark as Read -->
                                {% if not referral.is_read and not referral.is_reviewed %}
                                <button type="button" class="btn btn-sm btn-outline-success"
                                        onclick="markAsRead({{ referral.id }})">
                                    <i class="bi bi-check-circle me-1"></i>Read
                                </button>
                                {% endif %}

                                <!-- Mark as Reviewed -->
                                {% if not referral.is_reviewed %}
                                <form method="post" action="{{ url_for('admin.review_referral', referral_id=referral.id) }}" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-info">
                                        <i class="bi bi-eye-check me-1"></i>Review
                                    </button>
                                </form>
                                {% endif %}
                            </div>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7" class="text-center py-4">
                            <div class="text-muted">
                                <i class="bi bi-inbox fs-1"></i>
                                <p class="mt-2">No referrals found</p>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
function markAsRead(referralId) {
    fetch(`{{ url_for('admin.mark_referral_read', referral_id=0) }}`.replace('0', referralId), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Error marking referral as read');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error marking referral as read');
    });
}

function toggleAll() {
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    const checkboxes = document.querySelectorAll('.referral-checkbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
}

function selectAll() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
    });
    selectAllCheckbox.checked = true;
}

function selectNone() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
    selectAllCheckbox.checked = false;
}
</script>
{% endblock %}
'''
        with open(referrals_path, 'w') as f:
            f.write(referrals_content)

def create_base_templates():
    templates_dir = app.template_folder
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    # Base template
    base_path = os.path.join(templates_dir, 'base.html')
    if not os.path.exists(base_path):
        base_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}ITR Management System{% endblock %}</title>

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">

    <style>
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
        .footer {
            margin-top: 3rem;
            padding: 1.5rem 0;
            background-color: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="bi bi-calculator me-2"></i>ITR Management System
            </a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    {% if session.user_id %}
                        {% if session.is_admin %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('admin.dashboard') }}">
                                <i class="bi bi-speedometer2 me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('admin.referrals') }}">
                                <i class="bi bi-share me-1"></i>Referrals
                            </a>
                        </li>
                        {% else %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('client.dashboard') }}">
                                <i class="bi bi-speedometer2 me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('client.refer') }}">
                                <i class="bi bi-share me-1"></i>Refer Friend
                            </a>
                        </li>
                        {% endif %}
                    {% endif %}
                </ul>

                <ul class="navbar-nav">
                    {% if session.user_id %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle me-1"></i>{{ session.username }}
                        </a>
                        <ul class="dropdown-menu">
                            {% if session.is_admin %}
                            <li><a class="dropdown-item" href="{{ url_for('admin.logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Logout
                            </a></li>
                            {% else %}
                            <li><a class="dropdown-item" href="{{ url_for('client.profile') }}">
                                <i class="bi bi-person me-1"></i>Profile
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('client.logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Logout
                            </a></li>
                            {% endif %}
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('admin.login') }}">
                            <i class="bi bi-shield-lock me-1"></i>Admin Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('client.login') }}">
                            <i class="bi bi-person me-1"></i>Client Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('register') }}">
                            <i class="bi bi-person-plus me-1"></i>Register
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ 'danger' if category == 'error' else 'success' if category == 'success' else 'info' if category == 'info' else 'warning' }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <!-- Main Content -->
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p class="text-muted">&copy; 2024 ITR Management System. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-end">
                    <p class="text-muted">Built with Flask & Bootstrap</p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''
        with open(base_path, 'w') as f:
            f.write(base_content)

    # Index template
    index_path = os.path.join(templates_dir, 'index.html')
    if not os.path.exists(index_path):
        index_content = '''
{% extends 'base.html' %}

{% block title %}Home - ITR Management System{% endblock %}

{% block content %}
<div class="row">
    <div class="col-lg-8 mx-auto text-center">
        <h1 class="display-4 mb-4">Welcome to ITR Management System</h1>
        <p class="lead mb-5">Streamline your income tax return filing process with our comprehensive management system.</p>

        <div class="row">
            <div
'''
        with open(index_path, 'w') as f:
            f.write(index_content)

def create_referrals_template():
    templates_dir = os.path.join(app.template_folder, 'admin')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    referrals_path = os.path.join(templates_dir, 'referrals.html')
    if not os.path.exists(referrals_path):
        referrals_content = '''
{% extends 'base.html' %}

{% block title %}Referrals Management{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-share me-2"></i>Referrals Management</h2>
    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-primary">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<!-- Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body text-center">
                <h3>{{ stats.total }}</h3>
                <p class="mb-0">Total Referrals</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body text-center">
                <h3>{{ stats.pending }}</h3>
                <p class="mb-0">Pending</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body text-center">
                <h3>{{ stats.contacted }}</h3>
                <p class="mb-0">Contacted</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body text-center">
                <h3>{{ stats.converted }}</h3>
                <p class="mb-0">Converted</p>
            </div>
        </div>
    </div>
</div>

<!-- Search and Filter -->
<div class="card mb-4">
    <div class="card-body">
        <form method="get" class="row g-3">
            <div class="col-md-6">
                <label for="search" class="form-label">Search</label>
                <input type="text" class="form-control" id="search" name="search"
                       value="{{ search }}" placeholder="Search by name, email, or referrer...">
            </div>
            <div class="col-md-4">
                <label for="status" class="form-label">Status Filter</label>
                <select class="form-select" id="status" name="status">
                    <option value="">All Statuses</option>
                    <option value="Pending" {{ 'selected' if status_filter == 'Pending' }}>Pending</option>
                    <option value="Contacted" {{ 'selected' if status_filter == 'Contacted' }}>Contacted</option>
                    <option value="Converted" {{ 'selected' if status_filter == 'Converted' }}>Converted</option>
                    <option value="Rejected" {{ 'selected' if status_filter == 'Rejected' }}>Rejected</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Bulk Actions -->
<div class="card mb-4">
    <div class="card-body">
        <form method="post" action="{{ url_for('admin.bulk_referral_action') }}" id="bulkForm">
            <div class="row g-3 align-items-end">
                <div class="col-md-4">
                    <label for="bulkAction" class="form-label">Bulk Action</label>
                    <select class="form-select" id="bulkAction" name="action" required>
                        <option value="">Select Action</option>
                        <option value="mark_read">Mark as Read</option>
                        <option value="Pending">Set Status: Pending</option>
                        <option value="Contacted">Set Status: Contacted</option>
                        <option value="Converted">Set Status: Converted</option>
                        <option value="Rejected">Set Status: Rejected</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-warning" onclick="return confirm('Apply action to selected referrals?')">
                        <i class="bi bi-lightning me-1"></i>Apply to Selected
                    </button>
                </div>
                <div class="col-md-4 text-end">
                    <button type="button" class="btn btn-outline-secondary" onclick="selectAll()">Select All</button>
                    <button type="button" class="btn btn-outline-secondary" onclick="selectNone()">Select None</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Referrals Table -->
<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">All Referrals ({{ referrals|length }})</h5>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th width="50">
                            <input type="checkbox" id="selectAllCheckbox" onchange="toggleAll()">
                        </th>
                        <th>Referrer</th>
                        <th>Referred Person</th>
                        <th>Contact Info</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for referral in referrals %}
                    <tr class="{% if not referral.is_reviewed %}table-warning{% endif %}">
                        <td>
                            <input type="checkbox" name="referral_ids" value="{{ referral.id }}"
                                   form="bulkForm" class="referral-checkbox">
                        </td>
                        <td>
                            <strong>{{ referral.client_name or 'Unknown' }}</strong>
                        </td>
                        <td>
                            <div>
                                <strong>{{ referral.referred_name }}</strong>
                                {% if referral.referred_client_id %}
                                <span class="badge bg-success ms-1">Registered</span>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <div class="small">
                                <div><i class="bi bi-envelope me-1"></i>{{ referral.referred_email }}</div>
                                {% if referral.referred_phone %}
                                <div><i class="bi bi-telephone me-1"></i>{{ referral.referred_phone }}</div>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <small>{{ referral.created_at }}</small>
                        </td>
                        <td>
                            {% if referral.status %}
                            <span class="badge bg-{{ 'success' if referral.status == 'Converted' else 'primary' if referral.status == 'Contacted' else 'warning' if referral.status == 'Pending' else 'danger' }}">
                                {{ referral.status }}
                            </span>
                            {% else %}
                            <span class="badge bg-secondary">No Status</span>
                            {% endif %}

                            {% if not referral.is_read and not referral.is_reviewed %}
                            <span class="badge bg-danger">Unread</span>
                            {% endif %}
                        </td>
                        <td>
                            <div class="btn-group" role="group">
                                <!-- Status Update -->
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-primary dropdown-toggle" type="button"
                                            data-bs-toggle="dropdown" aria-expanded="false">
                                        Status
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Pending">
                                                <button type="submit" class="dropdown-item">Pending</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Contacted">
                                                <button type="submit" class="dropdown-item">Contacted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Converted">
                                                <button type="submit" class="dropdown-item">Converted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Rejected">
                                                <button type="submit" class="dropdown-item">Rejected</button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>

                                <!-- Mark as Read -->
                                {% if not referral.is_read and not referral.is_reviewed %}
                                <button type="button" class="btn btn-sm btn-outline-success"
                                        onclick="markAsRead({{ referral.id }})">
                                    <i class="bi bi-check-circle me-1"></i>Read
                                </button>
                                {% endif %}

                                <!-- Mark as Reviewed -->
                                {% if not referral.is_reviewed %}
                                <form method="post" action="{{ url_for('admin.review_referral', referral_id=referral.id) }}" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-info">
                                        <i class="bi bi-eye-check me-1"></i>Review
                                    </button>
                                </form>
                                {% endif %}
                            </div>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7" class="text-center py-4">
                            <div class="text-muted">
                                <i class="bi bi-inbox fs-1"></i>
                                <p class="mt-2">No referrals found</p>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
function markAsRead(referralId) {
    fetch(`{{ url_for('admin.mark_referral_read', referral_id=0) }}`.replace('0', referralId), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Error marking referral as read');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error marking referral as read');
    });
}

function toggleAll() {
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    const checkboxes = document.querySelectorAll('.referral-checkbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
}

function selectAll() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
    });
    selectAllCheckbox.checked = true;
}

function selectNone() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
    selectAllCheckbox.checked = false;
}
</script>
{% endblock %}
'''
        with open(referrals_path, 'w') as f:
            f.write(referrals_content)

def reset_database():
    """Reset the database with updated schema including is_active field"""
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
        print("Database initialized with updated schema including is_active field")

def migrate_database():
    """Migrate existing database to add missing columns"""
    try:
        db = get_db()

        # Check if is_active column exists in clients table
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'is_active' not in columns:
            print("Adding is_active column to clients table...")
            db.execute('ALTER TABLE clients ADD COLUMN is_active INTEGER DEFAULT 1')
            db.commit()
            print("Added is_active column successfully")

        if 'deactivated_at' not in columns:
            print("Adding deactivated_at column to clients table...")
            db.execute('ALTER TABLE clients ADD COLUMN deactivated_at TIMESTAMP NULL')
            db.commit()
            print("Added deactivated_at column successfully")
            
    except Exception as e:
        print(f"Error during database migration: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()

def create_base_templates():
    templates_dir = app.template_folder
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Base template
    base_path = os.path.join(templates_dir, 'base.html')
    if not os.path.exists(base_path):
        base_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}ITR Management System{% endblock %}</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    
    <style>
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
        .footer {
            margin-top: 3rem;
            padding: 1.5rem 0;
            background-color: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('index') }}">
                <i class="bi bi-calculator me-2"></i>ITR Management System
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    {% if session.user_id %}
                        {% if session.is_admin %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('admin.dashboard') }}">
                                <i class="bi bi-speedometer2 me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('admin.referrals') }}">
                                <i class="bi bi-share me-1"></i>Referrals
                            </a>
                        </li>
                        {% else %}
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('client.dashboard') }}">
                                <i class="bi bi-speedometer2 me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="{{ url_for('client.refer') }}">
                                <i class="bi bi-share me-1"></i>Refer Friend
                            </a>
                        </li>
                        {% endif %}
                    {% endif %}
                </ul>
                
                <ul class="navbar-nav">
                    {% if session.user_id %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle me-1"></i>{{ session.username }}
                        </a>
                        <ul class="dropdown-menu">
                            {% if session.is_admin %}
                            <li><a class="dropdown-item" href="{{ url_for('admin.logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Logout
                            </a></li>
                            {% else %}
                            <li><a class="dropdown-item" href="{{ url_for('client.profile') }}">
                                <i class="bi bi-person me-1"></i>Profile
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('client.logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Logout
                            </a></li>
                            {% endif %}
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('admin.login') }}">
                            <i class="bi bi-shield-lock me-1"></i>Admin Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('client.login') }}">
                            <i class="bi bi-person me-1"></i>Client Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('register') }}">
                            <i class="bi bi-person-plus me-1"></i>Register
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ 'danger' if category == 'error' else 'success' if category == 'success' else 'info' if category == 'info' else 'warning' }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <!-- Main Content -->
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>

    <!-- Footer -->
    <footer class="footer mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p class="text-muted">&copy; 2024 ITR Management System. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-end">
                    <p class="text-muted">Built with Flask & Bootstrap</p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''
        with open(base_path, 'w') as f:
            f.write(base_content)
    
    # Index template
    index_path = os.path.join(templates_dir, 'index.html')
    if not os.path.exists(index_path):
        index_content = '''
{% extends 'base.html' %}

{% block title %}Home - ITR Management System{% endblock %}

{% block content %}
<div class="row">
    <div class="col-lg-8 mx-auto text-center">
        <h1 class="display-4 mb-4">Welcome to ITR Management System</h1>
        <p class="lead mb-5">Streamline your income tax return filing process with our comprehensive management system.</p>
        
        <div class="row">
            <div
'''
        with open(index_path, 'w') as f:
            f.write(index_content)

def create_referrals_template():
    templates_dir = os.path.join(app.template_folder, 'admin')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    referrals_path = os.path.join(templates_dir, 'referrals.html')
    if not os.path.exists(referrals_path):
        referrals_content = '''
{% extends 'base.html' %}

{% block title %}Referrals Management{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-share me-2"></i>Referrals Management</h2>
    <a href="{{ url_for('admin.dashboard') }}" class="btn btn-primary">
        <i class="bi bi-speedometer2 me-1"></i>Back to Dashboard
    </a>
</div>

<!-- Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body text-center">
                <h3>{{ stats.total }}</h3>
                <p class="mb-0">Total Referrals</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body text-center">
                <h3>{{ stats.pending }}</h3>
                <p class="mb-0">Pending</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body text-center">
                <h3>{{ stats.contacted }}</h3>
                <p class="mb-0">Contacted</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body text-center">
                <h3>{{ stats.converted }}</h3>
                <p class="mb-0">Converted</p>
            </div>
        </div>
    </div>
</div>

<!-- Search and Filter -->
<div class="card mb-4">
    <div class="card-body">
        <form method="get" class="row g-3">
            <div class="col-md-6">
                <label for="search" class="form-label">Search</label>
                <input type="text" class="form-control" id="search" name="search"
                       value="{{ search }}" placeholder="Search by name, email, or referrer...">
            </div>
            <div class="col-md-4">
                <label for="status" class="form-label">Status Filter</label>
                <select class="form-select" id="status" name="status">
                    <option value="">All Statuses</option>
                    <option value="Pending" {{ 'selected' if status_filter == 'Pending' }}>Pending</option>
                    <option value="Contacted" {{ 'selected' if status_filter == 'Contacted' }}>Contacted</option>
                    <option value="Converted" {{ 'selected' if status_filter == 'Converted' }}>Converted</option>
                    <option value="Rejected" {{ 'selected' if status_filter == 'Rejected' }}>Rejected</option>
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-search me-1"></i>Filter
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Bulk Actions -->
<div class="card mb-4">
    <div class="card-body">
        <form method="post" action="{{ url_for('admin.bulk_referral_action') }}" id="bulkForm">
            <div class="row g-3 align-items-end">
                <div class="col-md-4">
                    <label for="bulkAction" class="form-label">Bulk Action</label>
                    <select class="form-select" id="bulkAction" name="action" required>
                        <option value="">Select Action</option>
                        <option value="mark_read">Mark as Read</option>
                        <option value="Pending">Set Status: Pending</option>
                        <option value="Contacted">Set Status: Contacted</option>
                        <option value="Converted">Set Status: Converted</option>
                        <option value="Rejected">Set Status: Rejected</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-warning" onclick="return confirm('Apply action to selected referrals?')">
                        <i class="bi bi-lightning me-1"></i>Apply to Selected
                    </button>
                </div>
                <div class="col-md-4 text-end">
                    <button type="button" class="btn btn-outline-secondary" onclick="selectAll()">Select All</button>
                    <button type="button" class="btn btn-outline-secondary" onclick="selectNone()">Select None</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Referrals Table -->
<div class="card shadow">
    <div class="card-header bg-primary text-white">
        <h5 class="mb-0">All Referrals ({{ referrals|length }})</h5>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                    <tr>
                        <th width="50">
                            <input type="checkbox" id="selectAllCheckbox" onchange="toggleAll()">
                        </th>
                        <th>Referrer</th>
                        <th>Referred Person</th>
                        <th>Contact Info</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for referral in referrals %}
                    <tr class="{% if not referral.is_reviewed %}table-warning{% endif %}">
                        <td>
                            <input type="checkbox" name="referral_ids" value="{{ referral.id }}"
                                   form="bulkForm" class="referral-checkbox">
                        </td>
                        <td>
                            <strong>{{ referral.client_name or 'Unknown' }}</strong>
                        </td>
                        <td>
                            <div>
                                <strong>{{ referral.referred_name }}</strong>
                                {% if referral.referred_client_id %}
                                <span class="badge bg-success ms-1">Registered</span>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <div class="small">
                                <div><i class="bi bi-envelope me-1"></i>{{ referral.referred_email }}</div>
                                {% if referral.referred_phone %}
                                <div><i class="bi bi-telephone me-1"></i>{{ referral.referred_phone }}</div>
                                {% endif %}
                            </div>
                        </td>
                        <td>
                            <small>{{ referral.created_at }}</small>
                        </td>
                        <td>
                            {% if referral.status %}
                            <span class="badge bg-{{ 'success' if referral.status == 'Converted' else 'primary' if referral.status == 'Contacted' else 'warning' if referral.status == 'Pending' else 'danger' }}">
                                {{ referral.status }}
                            </span>
                            {% else %}
                            <span class="badge bg-secondary">No Status</span>
                            {% endif %}

                            {% if not referral.is_read and not referral.is_reviewed %}
                            <span class="badge bg-danger">Unread</span>
                            {% endif %}
                        </td>
                        <td>
                            <div class="btn-group" role="group">
                                <!-- Status Update -->
                                <div class="dropdown">
                                    <button class="btn btn-sm btn-outline-primary dropdown-toggle" type="button"
                                            data-bs-toggle="dropdown" aria-expanded="false">
                                        Status
                                    </button>
                                    <ul class="dropdown-menu">
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Pending">
                                                <button type="submit" class="dropdown-item">Pending</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Contacted">
                                                <button type="submit" class="dropdown-item">Contacted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Converted">
                                                <button type="submit" class="dropdown-item">Converted</button>
                                            </form>
                                        </li>
                                        <li>
                                            <form method="post" action="{{ url_for('admin.update_referral_status', referral_id=referral.id) }}" class="d-inline">
                                                <input type="hidden" name="status" value="Rejected">
                                                <button type="submit" class="dropdown-item">Rejected</button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>

                                <!-- Mark as Read -->
                                {% if not referral.is_read and not referral.is_reviewed %}
                                <button type="button" class="btn btn-sm btn-outline-success"
                                        onclick="markAsRead({{ referral.id }})">
                                    <i class="bi bi-check-circle me-1"></i>Read
                                </button>
                                {% endif %}

                                <!-- Mark as Reviewed -->
                                {% if not referral.is_reviewed %}
                                <form method="post" action="{{ url_for('admin.review_referral', referral_id=referral.id) }}" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-info">
                                        <i class="bi bi-eye-check me-1"></i>Review
                                    </button>
                                </form>
                                {% endif %}
                            </div>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="7" class="text-center py-4">
                            <div class="text-muted">
                                <i class="bi bi-inbox fs-1"></i>
                                <p class="mt-2">No referrals found</p>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
function markAsRead(referralId) {
    fetch(`{{ url_for('admin.mark_referral_read', referral_id=0) }}`.replace('0', referralId), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Error marking referral as read');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error marking referral as read');
    });
}

function toggleAll() {
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    const checkboxes = document.querySelectorAll('.referral-checkbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
}

function selectAll() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
    });
    selectAllCheckbox.checked = true;
}

function selectNone() {
    const checkboxes = document.querySelectorAll('.referral-checkbox');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
    selectAllCheckbox.checked = false;
}
</script>
{% endblock %}
'''
        with open(referrals_path, 'w') as f:
            f.write(referrals_content)

def reset_database():
    """Reset the database with updated schema including is_active field"""
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
        print("Database initialized with updated schema including is_active field")

def migrate_database():
    """Migrate existing database to add missing columns"""
    try:
        db = get_db()

        # Check if is_active column exists in clients table
        cursor = db.execute("PRAGMA table_info(clients)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'is_active' not in columns:
            print("Adding is_active column to clients table...")
            db.execute('ALTER TABLE clients ADD COLUMN is_active INTEGER DEFAULT 1')
            db.commit()
            print("Added is_active column successfully")

        if 'deactivated_at' not in columns:
            print("Adding deactivated_at column to clients table...")
            db.execute('ALTER TABLE clients ADD COLUMN deactivated_at TIMESTAMP NULL')
            db.commit()
            print("Added deactivated_at column successfully")
            
    except Exception as e:
        print(f"Error during database migration: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    # Create necessary files and directories
    create_schema_file()
    create_base_templates()
    create_client_templates()
    create_admin_templates()
    create_referrals_template()  # Add this line
    
    # Check if database exists, if not initialize it
    if not os.path.exists('database.db'):
        init_db()
        print("Database initialized with sample data")
    else:
        # Migrate existing database to add missing columns
        with app.app_context():
            migrate_database()
    
    # Run the app
    app.run(debug=DEBUG)
