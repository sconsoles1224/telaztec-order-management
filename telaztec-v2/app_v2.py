from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import os
from functools import wraps
import hashlib
import pandas as pd
import io

# Try importing PyMuPDF for PDF processing
try:
    import fitz
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    print("Warning: PyMuPDF not available. PDF processing will be disabled.")

import re

app = Flask(__name__)
app.secret_key = 'telaztec_secret_key_2025_v2'

# Configuration
UPLOAD_FOLDER = 'telaztec-v2/uploads'
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup - V2 uses separate database
DATABASE = 'telaztec-v2/telaztec_orders_v2.db'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF using PyMuPDF"""
    if not PDF_SUPPORT:
        return ""
    
    try:
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        return text
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
        return ""

def parse_delivery_data_from_text(text):
    """Parse delivery data from extracted PDF text using regex patterns"""
    deliveries = []
    
    if not text.strip():
        return deliveries
    
    # Common patterns for purchase order data
    patterns = {
        'po_number': r'(?:PO|Purchase Order|P\.O\.)\s*[#:]?\s*([A-Z0-9\-]+)',
        'customer': r'(?:Bill To|Customer|Vendor):\s*([A-Za-z\s&,.-]+)',
        'part_number': r'(?:Part|Item|SKU)\s*[#:]?\s*([A-Z0-9\-]+)',
        'quantity': r'(?:Qty|Quantity):\s*(\d+)',
        'unit_price': r'(?:Unit Price|Price):\s*\$?(\d+\.?\d*)',
        'date': r'(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})'
    }
    
    # Extract basic information
    po_match = re.search(patterns['po_number'], text, re.IGNORECASE)
    customer_match = re.search(patterns['customer'], text, re.IGNORECASE)
    
    po_number = po_match.group(1).strip() if po_match else "EXTRACTED_PO"
    customer = customer_match.group(1).strip() if customer_match else "EXTRACTED_CUSTOMER"
    
    # Look for line items (simplified approach)
    lines = text.split('\n')
    line_number = 1
    
    for line in lines:
        # Look for lines that might contain part numbers and quantities
        if re.search(r'[A-Z0-9\-]{3,}', line) and re.search(r'\d+', line):
            # Try to extract part number
            part_match = re.search(r'([A-Z0-9\-]{3,})', line)
            qty_match = re.search(r'(\d+)', line)
            price_match = re.search(r'\$?(\d+\.?\d*)', line)
            
            if part_match and qty_match:
                try:
                    unit_price = float(price_match.group(1)) if price_match else 0.0
                    delivery_quantity = int(qty_match.group(1))
                    
                    delivery_data = {
                        'customer': customer,
                        'po_number': po_number,
                        'line_number': str(line_number),
                        'customer_part_number': part_match.group(1),
                        'unit_price': unit_price,
                        'telaztec_part_number': f"TZ-{part_match.group(1)}",
                        'rar': "TBD",
                        'delivery_quantity': delivery_quantity,
                        'delivery_date': datetime.now().strftime('%Y-%m-%d'),
                        'line_total_price': unit_price * delivery_quantity
                    }
                    
                    deliveries.append(delivery_data)
                    line_number += 1
                    
                except (ValueError, AttributeError):
                    continue
    
    return deliveries

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
            flash('Login successful! Welcome to TelAztec V2', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login_v2.html')

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
    
    return render_template('dashboard_v2.html', 
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
    
    return render_template('add_delivery_v2.html')

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
    
    return render_template('po_log_v2.html', 
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
    
    return render_template('delivery_log_v2.html', 
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
    
    return render_template('po_details_v2.html', 
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
    
    return render_template('edit_delivery_v2.html', delivery=delivery)

# NEW V2 ROUTES

@app.route('/upload')
@admin_required
def upload_page():
    return render_template('upload_v2.html', pdf_support=PDF_SUPPORT)

@app.route('/upload_excel', methods=['POST'])
@admin_required
def upload_excel():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('upload_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('upload_page'))
    
    if file and allowed_file(file.filename) and file.filename.rsplit('.', 1)[1].lower() in ['xlsx', 'xls']:
        try:
            # Read Excel file
            df = pd.read_excel(file)
            
            # Expected columns mapping
            required_columns = [
                'Customer', 'PO Number', 'Line Number', 'Customer Part Number',
                'Unit Price', 'TelAztec Part Number', 'RAR', 'Delivery Quantity', 'Delivery Date'
            ]
            
            # Check if required columns exist
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                flash(f'Missing required columns: {", ".join(missing_columns)}', 'error')
                return redirect(url_for('upload_page'))
            
            # Process and insert data
            conn = get_db_connection()
            
            successful_imports = 0
            errors = []
            
            for index, row in df.iterrows():
                try:
                    delivery_number = get_next_delivery_number()
                    
                    # Convert delivery date
                    delivery_date = row['Delivery Date']
                    if pd.notna(delivery_date):
                        if isinstance(delivery_date, pd.Timestamp):
                            delivery_date = delivery_date.strftime('%Y-%m-%d')
                        else:
                            try:
                                parsed_date = pd.to_datetime(delivery_date)
                                delivery_date = parsed_date.strftime('%Y-%m-%d')
                            except:
                                delivery_date = str(delivery_date)
                    else:
                        delivery_date = datetime.now().strftime('%Y-%m-%d')
                    
                    unit_price = float(row['Unit Price']) if pd.notna(row['Unit Price']) else 0.0
                    delivery_quantity = int(row['Delivery Quantity']) if pd.notna(row['Delivery Quantity']) else 0
                    line_total_price = unit_price * delivery_quantity
                    
                    conn.execute('''
                        INSERT INTO delivery_log (delivery_number, customer, po_number, line_number,
                                                customer_part_number, unit_price, telaztec_part_number,
                                                rar, delivery_quantity, delivery_date, line_total_price)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        delivery_number,
                        str(row['Customer']) if pd.notna(row['Customer']) else '',
                        str(row['PO Number']) if pd.notna(row['PO Number']) else '',
                        str(row['Line Number']) if pd.notna(row['Line Number']) else '',
                        str(row['Customer Part Number']) if pd.notna(row['Customer Part Number']) else '',
                        unit_price,
                        str(row['TelAztec Part Number']) if pd.notna(row['TelAztec Part Number']) else '',
                        str(row['RAR']) if pd.notna(row['RAR']) else '',
                        delivery_quantity,
                        delivery_date,
                        line_total_price
                    ))
                    
                    successful_imports += 1
                    
                except Exception as e:
                    errors.append(f'Row {index + 2}: {str(e)}')
            
            conn.commit()
            conn.close()
            
            if successful_imports > 0:
                flash(f'Successfully imported {successful_imports} deliveries!', 'success')
            
            if errors:
                flash(f'Errors encountered: {"; ".join(errors[:5])}', 'error')
            
            return redirect(url_for('delivery_log'))
            
        except Exception as e:
            flash(f'Error processing Excel file: {str(e)}', 'error')
            return redirect(url_for('upload_page'))
    
    else:
        flash('Invalid file type. Please upload an Excel file (.xlsx or .xls)', 'error')
        return redirect(url_for('upload_page'))

@app.route('/upload_pdf', methods=['POST'])
@admin_required
def upload_pdf():
    if not PDF_SUPPORT:
        flash('PDF processing is not available. PyMuPDF library is required.', 'error')
        return redirect(url_for('upload_page'))
    
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('upload_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('upload_page'))
    
    if file and allowed_file(file.filename) and file.filename.rsplit('.', 1)[1].lower() == 'pdf':
        try:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Extract text from PDF
            text = extract_text_from_pdf(filepath)
            
            if not text.strip():
                flash('Could not extract text from PDF. Please check if the PDF contains readable text.', 'error')
                os.remove(filepath)
                return redirect(url_for('upload_page'))
            
            # Parse delivery data from text
            deliveries = parse_delivery_data_from_text(text)
            
            if not deliveries:
                flash('Could not extract delivery data from PDF. Please check the document format or add deliveries manually.', 'error')
                os.remove(filepath)
                return redirect(url_for('upload_page'))
            
            # Insert parsed data into database
            conn = get_db_connection()
            
            successful_imports = 0
            
            for delivery_data in deliveries:
                try:
                    delivery_number = get_next_delivery_number()
                    
                    conn.execute('''
                        INSERT INTO delivery_log (delivery_number, customer, po_number, line_number,
                                                customer_part_number, unit_price, telaztec_part_number,
                                                rar, delivery_quantity, delivery_date, line_total_price)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        delivery_number,
                        delivery_data['customer'],
                        delivery_data['po_number'],
                        delivery_data['line_number'],
                        delivery_data['customer_part_number'],
                        delivery_data['unit_price'],
                        delivery_data['telaztec_part_number'],
                        delivery_data['rar'],
                        delivery_data['delivery_quantity'],
                        delivery_data['delivery_date'],
                        delivery_data['line_total_price']
                    ))
                    
                    successful_imports += 1
                    
                except Exception as e:
                    print(f"Error inserting delivery: {e}")
            
            conn.commit()
            conn.close()
            
            # Clean up uploaded file
            os.remove(filepath)
            
            if successful_imports > 0:
                flash(f'Successfully extracted and imported {successful_imports} deliveries from PDF!', 'success')
            else:
                flash('No deliveries could be extracted from the PDF.', 'error')
            
            return redirect(url_for('delivery_log'))
            
        except Exception as e:
            flash(f'Error processing PDF file: {str(e)}', 'error')
            if 'filepath' in locals() and os.path.exists(filepath):
                os.remove(filepath)
            return redirect(url_for('upload_page'))
    
    else:
        flash('Invalid file type. Please upload a PDF file.', 'error')
        return redirect(url_for('upload_page'))

@app.route('/reset_database', methods=['POST'])
@admin_required
def reset_database():
    try:
        conn = get_db_connection()
        
        # Reset delivery counter to 0
        current_year = datetime.now().year
        year_suffix = str(current_year)[-2:]
        
        conn.execute('''
            UPDATE system_settings 
            SET setting_value = '0', last_updated = CURRENT_TIMESTAMP
            WHERE setting_name = ?
        ''', ('delivery_counter_' + year_suffix,))
        
        # Delete all deliveries
        conn.execute('DELETE FROM delivery_log')
        
        conn.commit()
        conn.close()
        
        flash('Database reset successfully! All delivery data has been cleared.', 'success')
    except Exception as e:
        flash(f'Error resetting database: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/export_excel')
@admin_required
def export_excel():
    try:
        conn = get_db_connection()
        
        # Export deliveries to Excel
        df = pd.read_sql_query('''
            SELECT delivery_number as "Delivery Number",
                   customer as "Customer",
                   po_number as "PO Number", 
                   line_number as "Line Number",
                   customer_part_number as "Customer Part Number",
                   unit_price as "Unit Price",
                   telaztec_part_number as "TelAztec Part Number",
                   rar as "RAR",
                   delivery_quantity as "Delivery Quantity",
                   delivery_date as "Delivery Date",
                   line_total_price as "Line Total Price",
                   created_date as "Created Date"
            FROM delivery_log 
            ORDER BY created_date DESC
        ''', conn)
        
        conn.close()
        
        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Deliveries', index=False)
        
        output.seek(0)
        
        # Generate filename with current date
        filename = f'telaztec_deliveries_v2_{datetime.now().strftime("%Y%m%d")}.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f'Error exporting data: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 8081)))
