from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import os
from datetime import datetime
from functools import wraps
import hashlib

app = Flask(__name__)
app.secret_key = 'telaztec_secret_key_2025'

# Database setup
DATABASE = 'telaztec_orders.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    
    # Create users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer'
        )
    ''')
    
    # Create delivery log table (single source of truth)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS delivery_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_number TEXT UNIQUE NOT NULL,
            customer TEXT NOT NULL,
            po_number TEXT NOT NULL,
            line_number TEXT NOT NULL,
            customer_part_number TEXT NOT NULL,
            unit_price REAL NOT NULL,
            telaztec_part_number TEXT,
            rar TEXT,
            delivery_quantity INTEGER NOT NULL,
            delivery_date DATE NOT NULL,
            line_total_price REAL NOT NULL,
            created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create system settings table for auto-numbering
    conn.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_name TEXT UNIQUE NOT NULL,
            setting_value TEXT NOT NULL,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Initialize counters for current year
    current_year = datetime.now().year
    year_suffix = str(current_year)[-2:]
    
    conn.execute('''
        INSERT OR IGNORE INTO system_settings (setting_name, setting_value)
        VALUES (?, ?)
    ''', ('delivery_counter_' + year_suffix, '0'))
    
    # Create default admin user
    admin_password = hashlib.sha256('telaztec2025'.encode()).hexdigest()
    conn.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('admin', admin_password, 'admin'))
    
    conn.commit()
    conn.close()

def get_next_delivery_number():
    conn = get_db_connection()
    current_year = datetime.now().year
    year_suffix = str(current_year)[-2:]
    
    # Get current counter
    result = conn.execute('''
        SELECT setting_value FROM system_settings 
        WHERE setting_name = ?
    ''', ('delivery_counter_' + year_suffix,)).fetchone()
    
    if result:
        current_count = int(result['setting_value'])
    else:
        current_count = 0
    
    # Increment counter
    new_count = current_count + 1
    
    # Update counter in database
    conn.execute('''
        UPDATE system_settings 
        SET setting_value = ?, last_updated = CURRENT_TIMESTAMP
        WHERE setting_name = ?
    ''', (str(new_count), 'delivery_counter_' + year_suffix))
    
    conn.commit()
    conn.close()
    
    # Return formatted delivery number
    return f"DEL{year_suffix}{new_count:04d}"

def get_po_summary():
    """Calculate PO log summary from delivery data"""
    conn = get_db_connection()
    
    # Group deliveries by PO and customer part number to create PO summary
    po_summary = conn.execute('''
        SELECT 
            customer,
            po_number,
            customer_part_number,
            telaztec_part_number,
            rar,
            unit_price,
            SUM(delivery_quantity) as total_quantity,
            SUM(line_total_price) as total_price,
            MIN(created_date) as first_created,
            MAX(last_modified) as last_modified,
            COUNT(*) as delivery_count
        FROM delivery_log 
        GROUP BY customer, po_number, customer_part_number
        ORDER BY MAX(created_date) DESC
    ''').fetchall()
    
    conn.close()
    return po_summary

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        user = conn.execute('''
            SELECT * FROM users WHERE username = ? AND password_hash = ?
        ''', (username, password_hash)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    
    # Get summary statistics from deliveries
    total_deliveries = conn.execute('SELECT COUNT(*) as count FROM delivery_log').fetchone()['count']
    
    # Calculate unique POs
    unique_pos = conn.execute('''
        SELECT COUNT(DISTINCT po_number || customer_part_number) as count 
        FROM delivery_log
    ''').fetchone()['count']
    
    # Get recent deliveries
    recent_deliveries = conn.execute('''
        SELECT * FROM delivery_log 
        ORDER BY created_date DESC 
        LIMIT 5
    ''').fetchall()
    
    # Get upcoming deliveries (next 7 days)
    upcoming_deliveries = conn.execute('''
        SELECT * FROM delivery_log 
        WHERE delivery_date BETWEEN date('now') AND date('now', '+7 days')
        ORDER BY delivery_date ASC 
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         unique_pos=unique_pos,
                         total_deliveries=total_deliveries,
                         recent_deliveries=recent_deliveries,
                         upcoming_deliveries=upcoming_deliveries)

@app.route('/add_delivery', methods=['GET', 'POST'])
@admin_required
def add_delivery():
    if request.method == 'POST':
        delivery_number = get_next_delivery_number()
        customer = request.form['customer']
        po_number = request.form['po_number']
        line_number = request.form['line_number']
        customer_part_number = request.form['customer_part_number']
        unit_price = float(request.form['unit_price'])
        telaztec_part_number = request.form['telaztec_part_number']
        rar = request.form['rar']
        delivery_quantity = int(request.form['delivery_quantity'])
        delivery_date = request.form['delivery_date']
        line_total_price = unit_price * delivery_quantity
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO delivery_log (delivery_number, customer, po_number, line_number,
                                    customer_part_number, unit_price, telaztec_part_number,
                                    rar, delivery_quantity, delivery_date, line_total_price)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (delivery_number, customer, po_number, line_number, customer_part_number,
              unit_price, telaztec_part_number, rar, delivery_quantity, delivery_date, line_total_price))
        conn.commit()
        conn.close()
        
        flash(f'Delivery {delivery_number} added successfully!', 'success')
        return redirect(url_for('delivery_log'))
    
    return render_template('add_delivery.html')

@app.route('/po_log')
@login_required
def po_log():
    # Get filter parameters
    customer_filter = request.args.get('customer', '')
    part_filter = request.args.get('part', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    conn = get_db_connection()
    
    # Build query for PO summary with filters
    query = '''
        SELECT 
            customer,
            po_number,
            customer_part_number,
            telaztec_part_number,
            rar,
            unit_price,
            SUM(delivery_quantity) as total_quantity,
            SUM(line_total_price) as total_price,
            MIN(created_date) as first_created,
            MAX(last_modified) as last_modified,
            COUNT(*) as delivery_count
        FROM delivery_log 
        WHERE 1=1
    '''
    params = []
    
    if customer_filter:
        query += ' AND customer LIKE ?'
        params.append(f'%{customer_filter}%')
    
    if part_filter:
        query += ' AND (customer_part_number LIKE ? OR telaztec_part_number LIKE ?)'
        params.append(f'%{part_filter}%')
        params.append(f'%{part_filter}%')
    
    if date_from:
        query += ' AND created_date >= ?'
        params.append(date_from)
    
    if date_to:
        query += ' AND created_date <= ?'
        params.append(date_to + ' 23:59:59')
    
    query += ' GROUP BY customer, po_number, customer_part_number ORDER BY MAX(created_date) DESC'
    
    orders = conn.execute(query, params).fetchall()
    
    # Calculate totals
    total_revenue = sum(order['total_price'] for order in orders)
    total_quantity = sum(order['total_quantity'] for order in orders)
    
    conn.close()
    
    return render_template('po_log.html', 
                         orders=orders, 
                         total_revenue=total_revenue,
                         total_quantity=total_quantity,
                         customer_filter=customer_filter,
                         part_filter=part_filter,
                         date_from=date_from,
                         date_to=date_to)

@app.route('/delivery_log')
@login_required
def delivery_log():
    conn = get_db_connection()
    
    # Get filter parameters
    customer_filter = request.args.get('customer', '')
    part_filter = request.args.get('part', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Build query
    query = 'SELECT * FROM delivery_log WHERE 1=1'
    params = []
    
    if customer_filter:
        query += ' AND customer LIKE ?'
        params.append(f'%{customer_filter}%')
    
    if part_filter:
        query += ' AND (customer_part_number LIKE ? OR telaztec_part_number LIKE ?)'
        params.append(f'%{part_filter}%')
        params.append(f'%{part_filter}%')
    
    if date_from:
        query += ' AND delivery_date >= ?'
        params.append(date_from)
    
    if date_to:
        query += ' AND delivery_date <= ?'
        params.append(date_to)
    
    query += ' ORDER BY delivery_date DESC'
    
    deliveries = conn.execute(query, params).fetchall()
    
    # Calculate totals
    total_revenue = sum(delivery['line_total_price'] for delivery in deliveries)
    total_quantity = sum(delivery['delivery_quantity'] for delivery in deliveries)
    
    conn.close()
    
    return render_template('delivery_log.html', 
                         deliveries=deliveries, 
                         total_revenue=total_revenue,
                         total_quantity=total_quantity,
                         customer_filter=customer_filter,
                         part_filter=part_filter,
                         date_from=date_from,
                         date_to=date_to)

@app.route('/po_details/<customer>/<po_number>/<customer_part_number>')
@login_required
def po_details(customer, po_number, customer_part_number):
    """Show all deliveries for a specific PO line item"""
    conn = get_db_connection()
    
    deliveries = conn.execute('''
        SELECT * FROM delivery_log 
        WHERE customer = ? AND po_number = ? AND customer_part_number = ?
        ORDER BY delivery_date ASC
    ''', (customer, po_number, customer_part_number)).fetchall()
    
    # Calculate summary
    total_quantity = sum(d['delivery_quantity'] for d in deliveries)
    total_value = sum(d['line_total_price'] for d in deliveries)
    
    conn.close()
    
    return render_template('po_details.html', 
                         deliveries=deliveries,
                         customer=customer,
                         po_number=po_number,
                         customer_part_number=customer_part_number,
                         total_quantity=total_quantity,
                         total_value=total_value)

@app.route('/edit_delivery/<delivery_number>', methods=['GET', 'POST'])
@admin_required
def edit_delivery(delivery_number):
    conn = get_db_connection()
    
    if request.method == 'POST':
        customer = request.form['customer']
        po_number = request.form['po_number']
        line_number = request.form['line_number']
        customer_part_number = request.form['customer_part_number']
        unit_price = float(request.form['unit_price'])
        telaztec_part_number = request.form['telaztec_part_number']
        rar = request.form['rar']
        delivery_quantity = int(request.form['delivery_quantity'])
        delivery_date = request.form['delivery_date']
        line_total_price = unit_price * delivery_quantity
        
        conn.execute('''
            UPDATE delivery_log 
            SET customer = ?, po_number = ?, line_number = ?, customer_part_number = ?, 
                unit_price = ?, telaztec_part_number = ?, rar = ?, 
                delivery_quantity = ?, delivery_date = ?, line_total_price = ?, 
                last_modified = CURRENT_TIMESTAMP
            WHERE delivery_number = ?
        ''', (customer, po_number, line_number, customer_part_number, unit_price, 
              telaztec_part_number, rar, delivery_quantity, delivery_date, 
              line_total_price, delivery_number))
        conn.commit()
        conn.close()
        
        flash(f'Delivery {delivery_number} updated successfully!', 'success')
        return redirect(url_for('delivery_log'))
    
    delivery = conn.execute('''
        SELECT * FROM delivery_log WHERE delivery_number = ?
    ''', (delivery_number,)).fetchone()
    conn.close()
    
    if not delivery:
        flash('Delivery not found', 'error')
        return redirect(url_for('delivery_log'))
    
    return render_template('edit_delivery.html', delivery=delivery)

if __name__ == '__main__':
    init_database()
    import os
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
