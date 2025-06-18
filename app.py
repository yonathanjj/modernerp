from flask import Flask, request, jsonify, g, render_template, redirect, url_for, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import random

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Better secret key generation
app.config['DATABASE'] = 'erp.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout


# Database setup
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                brand TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                location TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                last_updated TEXT NOT NULL,
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                from_location TEXT NOT NULL,
                to_location TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                status TEXT NOT NULL,
                initiated_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (product_id) REFERENCES products (id),
                FOREIGN KEY (initiated_by) REFERENCES users (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT,
                location TEXT NOT NULL,
                total_amount REAL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sale_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sale_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                FOREIGN KEY (sale_id) REFERENCES sales (id),
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')

        # Create initial users if they don't exist
        default_users = [
            ('admin', 'admin123', 'admin'),
            ('warehouse', 'warehouse123', 'warehouse'),
            ('showroom', 'showroom123', 'showroom')
        ]

        for username, password, role in default_users:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if not cursor.fetchone():
                hashed_password = generate_password_hash(password)
                cursor.execute(
                    'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)',
                    (username, hashed_password, role, datetime.now().isoformat())
                )

        # Create sample products if none exist
        cursor.execute('SELECT id FROM products LIMIT 1')
        if not cursor.fetchone():
            sample_products = [
                ('Dr. Fixit LW+', 'Dr. Fixit', 'Liquid waterproofing compound', 1200),
                ('Pidilite Fevicol', 'Pidilite', 'Synthetic resin adhesive', 150),
                ('Asian Paints Primer', 'Asian Paints', 'Wall primer', 800),
                ('Berger Weathercoat', 'Berger', 'Exterior wall paint', 950)
            ]

            for name, brand, description, price in sample_products:
                cursor.execute(
                    'INSERT INTO products (name, brand, description, price, created_at) VALUES (?, ?, ?, ?, ?)',
                    (name, brand, description, price, datetime.now().isoformat())
                )

            # Add initial inventory
            cursor.execute('SELECT id FROM products')
            product_ids = [row[0] for row in cursor.fetchall()]
            for product_id in product_ids:
                for location in ['warehouse', 'showroom']:
                    quantity = 100 if location == 'warehouse' else 20
                    cursor.execute(
                        'INSERT INTO inventory (product_id, location, quantity, last_updated) VALUES (?, ?, ?, ?)',
                        (product_id, location, quantity, datetime.now().isoformat())
                    )

        db.commit()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login', next=request.url))
            if session.get('user_role') != role:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# API Endpoints
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not username or not password or not role:
        return jsonify({'error': 'Missing credentials'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    if user['role'] != role:
        return jsonify({'error': 'User does not have the selected role'}), 403

    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['user_role'] = user['role']

    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'message': 'Logout successful'})


@app.route('/api/inventory', methods=['GET'])
@login_required
def get_inventory():
    location = request.args.get('location', 'all')
    search = request.args.get('search', '')

    db = get_db()
    cursor = db.cursor()

    query = '''
        SELECT i.id, p.id as product_id, p.name, p.brand, p.price, i.location, i.quantity, i.last_updated 
        FROM inventory i
        JOIN products p ON i.product_id = p.id
        WHERE (p.name LIKE ? OR p.brand LIKE ?)
    '''
    params = [f'%{search}%', f'%{search}%']

    if location != 'all':
        query += ' AND i.location = ?'
        params.append(location)

    query += ' ORDER BY p.name'
    cursor.execute(query, params)

    inventory = [dict(row) for row in cursor.fetchall()]
    return jsonify(inventory)


@app.route('/api/inventory/<int:inventory_id>', methods=['DELETE'])
@login_required
def delete_inventory(inventory_id):
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute('DELETE FROM inventory WHERE id = ?', (inventory_id,))
        db.commit()
        return jsonify({'message': 'Inventory item deleted successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/inventory', methods=['POST'])
@login_required
def add_inventory():
    data = request.get_json()
    name = data.get('name')
    brand = data.get('brand')
    location = data.get('location')
    quantity = data.get('quantity')

    if not all([name, brand, location, quantity]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid quantity'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Check if product exists
        cursor.execute('SELECT id FROM products WHERE name = ? AND brand = ?', (name, brand))
        product = cursor.fetchone()

        if not product:
            # Create new product with default price
            cursor.execute('''
                INSERT INTO products (name, brand, description, price, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, brand, '', 0, datetime.now().isoformat()))
            product_id = cursor.lastrowid
        else:
            product_id = product['id']

        # Check if inventory exists for this product and location
        cursor.execute('''
            SELECT id, quantity FROM inventory 
            WHERE product_id = ? AND location = ?
        ''', (product_id, location))
        existing = cursor.fetchone()

        if existing:
            # Update existing inventory
            new_quantity = existing['quantity'] + quantity
            cursor.execute('''
                UPDATE inventory 
                SET quantity = ?, last_updated = ?
                WHERE id = ?
            ''', (new_quantity, datetime.now().isoformat(), existing['id']))
        else:
            # Create new inventory record
            cursor.execute('''
                INSERT INTO inventory (product_id, location, quantity, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (product_id, location, quantity, datetime.now().isoformat()))

        db.commit()
        return jsonify({'message': 'Inventory updated successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/transfers', methods=['GET'])
@login_required
def get_transfers():
    status = request.args.get('status', 'all')

    db = get_db()
    cursor = db.cursor()

    if status != 'all':
        cursor.execute('''
            SELECT t.*, p.name as product_name, u.username as initiated_by_name
            FROM transfers t
            JOIN products p ON t.product_id = p.id
            JOIN users u ON t.initiated_by = u.id
            WHERE t.status = ?
            ORDER BY t.created_at DESC
        ''', (status,))
    else:
        cursor.execute('''
            SELECT t.*, p.name as product_name, u.username as initiated_by_name
            FROM transfers t
            JOIN products p ON t.product_id = p.id
            JOIN users u ON t.initiated_by = u.id
            ORDER BY t.created_at DESC
        ''')

    transfers = [dict(row) for row in cursor.fetchall()]
    return jsonify(transfers)


@app.route('/api/transfers', methods=['POST'])
@login_required
def create_transfer():
    data = request.get_json()
    product_id = data.get('product_id')
    from_location = data.get('from_location')
    to_location = data.get('to_location')
    quantity = data.get('quantity')

    if not all([product_id, from_location, to_location, quantity]):
        return jsonify({'error': 'Missing required fields'}), 400

    if from_location == to_location:
        return jsonify({'error': 'Source and destination cannot be the same'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'error': 'Quantity must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid quantity'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Check if source has enough inventory
        cursor.execute('''
            SELECT quantity FROM inventory
            WHERE product_id = ? AND location = ?
        ''', (product_id, from_location))
        source_inventory = cursor.fetchone()

        if not source_inventory or source_inventory['quantity'] < quantity:
            return jsonify({'error': 'Insufficient inventory at source location'}), 400

        # Create transfer record
        cursor.execute('''
            INSERT INTO transfers (
                product_id, from_location, to_location, quantity, 
                status, initiated_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            product_id, from_location, to_location, quantity,
            'pending', session['user_id'], datetime.now().isoformat()
        ))

        transfer_id = cursor.lastrowid

        # For immediate transfers (not pending), process the transfer
        if to_location != 'customer':
            # Reduce source inventory
            cursor.execute('''
                UPDATE inventory
                SET quantity = quantity - ?, last_updated = ?
                WHERE product_id = ? AND location = ?
            ''', (quantity, datetime.now().isoformat(), product_id, from_location))

            # Check if destination inventory exists
            cursor.execute('''
                SELECT quantity FROM inventory
                WHERE product_id = ? AND location = ?
            ''', (product_id, to_location))
            dest_inventory = cursor.fetchone()

            if dest_inventory:
                # Update existing inventory
                cursor.execute('''
                    UPDATE inventory
                    SET quantity = quantity + ?, last_updated = ?
                    WHERE product_id = ? AND location = ?
                ''', (quantity, datetime.now().isoformat(), product_id, to_location))
            else:
                # Create new inventory record
                cursor.execute('''
                    INSERT INTO inventory (
                        product_id, location, quantity, last_updated
                    ) VALUES (?, ?, ?, ?)
                ''', (product_id, to_location, quantity, datetime.now().isoformat()))

            # Mark transfer as completed
            cursor.execute('''
                UPDATE transfers
                SET status = 'completed', completed_at = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), transfer_id))

        db.commit()
        return jsonify({'message': 'Transfer created successfully', 'transfer_id': transfer_id})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/transfers/<int:transfer_id>/complete', methods=['POST'])
@login_required
def complete_transfer(transfer_id):
    db = get_db()
    cursor = db.cursor()

    try:
        # Get transfer details
        cursor.execute('''
            SELECT * FROM transfers
            WHERE id = ? AND status = 'pending'
        ''', (transfer_id,))
        transfer = cursor.fetchone()

        if not transfer:
            return jsonify({'error': 'Transfer not found or already completed'}), 404

        # Check if source has enough inventory
        cursor.execute('''
            SELECT quantity FROM inventory
            WHERE product_id = ? AND location = ?
        ''', (transfer['product_id'], transfer['from_location']))
        source_inventory = cursor.fetchone()

        if not source_inventory or source_inventory['quantity'] < transfer['quantity']:
            return jsonify({'error': 'Insufficient inventory at source location'}), 400

        # Process the transfer
        # Reduce source inventory
        cursor.execute('''
            UPDATE inventory
            SET quantity = quantity - ?, last_updated = ?
            WHERE product_id = ? AND location = ?
        ''', (transfer['quantity'], datetime.now().isoformat(),
              transfer['product_id'], transfer['from_location']))

        # Check if destination inventory exists
        cursor.execute('''
            SELECT quantity FROM inventory
            WHERE product_id = ? AND location = ?
        ''', (transfer['product_id'], transfer['to_location']))
        dest_inventory = cursor.fetchone()

        if dest_inventory:
            # Update existing inventory
            cursor.execute('''
                UPDATE inventory
                SET quantity = quantity + ?, last_updated = ?
                WHERE product_id = ? AND location = ?
            ''', (transfer['quantity'], datetime.now().isoformat(),
                  transfer['product_id'], transfer['to_location']))
        else:
            # Create new inventory record
            cursor.execute('''
                INSERT INTO inventory (
                    product_id, location, quantity, last_updated
                ) VALUES (?, ?, ?, ?)
            ''', (transfer['product_id'], transfer['to_location'],
                  transfer['quantity'], datetime.now().isoformat()))

        # Mark transfer as completed
        cursor.execute('''
            UPDATE transfers
            SET status = 'completed', completed_at = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), transfer_id))

        db.commit()
        return jsonify({'message': 'Transfer completed successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/sales', methods=['GET'])
@login_required
def get_sales():
    location = request.args.get('location', 'all')
    search = request.args.get('search', '')

    db = get_db()
    cursor = db.cursor()

    query = '''
        SELECT s.*, u.username as created_by_name,
               (SELECT COUNT(*) FROM sale_items WHERE sale_id = s.id) as items_count
        FROM sales s
        JOIN users u ON s.created_by = u.id
        WHERE (s.customer_name LIKE ? OR u.username LIKE ?)
    '''
    params = [f'%{search}%', f'%{search}%']

    if location != 'all':
        query += ' AND s.location = ?'
        params.append(location)

    query += ' ORDER BY s.created_at DESC'
    cursor.execute(query, params)

    sales = [dict(row) for row in cursor.fetchall()]
    return jsonify(sales)


@app.route('/api/sales', methods=['POST'])
@login_required
def create_sale():
    data = request.get_json()
    customer_name = data.get('customer_name', '')
    location = data.get('location')
    items = data.get('items')

    if not location or not items:
        return jsonify({'error': 'Missing required fields'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Calculate total amount and validate items
        total_amount = 0
        for item in items:
            try:
                product_id = int(item['product_id'])
                quantity = int(item['quantity'])

                if quantity <= 0:
                    return jsonify({'error': 'Quantity must be positive'}), 400

                # Get product price
                cursor.execute('SELECT price FROM products WHERE id = ?', (product_id,))
                product = cursor.fetchone()
                if not product:
                    return jsonify({'error': f'Product with ID {product_id} not found'}), 404

                price = product['price']

                # Check inventory
                cursor.execute('''
                    SELECT quantity FROM inventory
                    WHERE product_id = ? AND location = ?
                ''', (product_id, location))
                inventory = cursor.fetchone()

                if not inventory or inventory['quantity'] < quantity:
                    return jsonify({'error': f'Insufficient inventory for product ID {product_id}'}), 400

                total_amount += price * quantity

            except (KeyError, ValueError):
                return jsonify({'error': 'Invalid item data'}), 400

        # Create sale record
        cursor.execute('''
            INSERT INTO sales (
                customer_name, location, total_amount, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?)
        ''', (customer_name, location, total_amount, session['user_id'], datetime.now().isoformat()))

        sale_id = cursor.lastrowid

        # Create sale items and update inventory
        for item in items:
            product_id = int(item['product_id'])
            quantity = int(item['quantity'])

            # Get product price
            cursor.execute('SELECT price FROM products WHERE id = ?', (product_id,))
            product = cursor.fetchone()
            price = product['price']

            cursor.execute('''
                INSERT INTO sale_items (
                    sale_id, product_id, quantity, unit_price
                ) VALUES (?, ?, ?, ?)
            ''', (sale_id, product_id, quantity, price))

            # Reduce inventory
            cursor.execute('''
                UPDATE inventory
                SET quantity = quantity - ?, last_updated = ?
                WHERE product_id = ? AND location = ?
            ''', (quantity, datetime.now().isoformat(), product_id, location))

        db.commit()
        return jsonify({
            'message': 'Sale created successfully',
            'sale_id': sale_id,
            'total_amount': total_amount
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        SELECT p.*, 
               (SELECT SUM(quantity) FROM inventory WHERE product_id = p.id AND location = 'warehouse') as warehouse_stock,
               (SELECT SUM(quantity) FROM inventory WHERE product_id = p.id AND location = 'showroom') as showroom_stock
        FROM products p
        ORDER BY p.name
    ''')

    products = [dict(row) for row in cursor.fetchall()]
    return jsonify(products)


@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    db = get_db()
    cursor = db.cursor()

    # Total inventory
    cursor.execute('SELECT SUM(quantity) as total FROM inventory')
    total_inventory = cursor.fetchone()['total'] or 0

    # Warehouse stock
    cursor.execute('SELECT SUM(quantity) as total FROM inventory WHERE location = "warehouse"')
    warehouse_stock = cursor.fetchone()['total'] or 0

    # Showroom stock
    cursor.execute('SELECT SUM(quantity) as total FROM inventory WHERE location = "showroom"')
    showroom_stock = cursor.fetchone()['total'] or 0

    # Pending transfers
    cursor.execute('SELECT COUNT(*) as total FROM transfers WHERE status = "pending"')
    pending_transfers = cursor.fetchone()['total'] or 0

    # Recent activity (transfers)
    cursor.execute('''
        SELECT t.*, p.name as product_name, u.username as initiated_by_name
        FROM transfers t
        JOIN products p ON t.product_id = p.id
        JOIN users u ON t.initiated_by = u.id
        ORDER BY t.created_at DESC
        LIMIT 5
    ''')
    recent_activity = [dict(row) for row in cursor.fetchall()]

    return jsonify({
        'total_inventory': total_inventory,
        'warehouse_stock': warehouse_stock,
        'showroom_stock': showroom_stock,
        'pending_transfers': pending_transfers,
        'recent_activity': recent_activity
    })


@app.route('/api/dashboard/charts/inventory', methods=['GET'])
@login_required
def get_inventory_chart_data():
    days = int(request.args.get('days', 7))

    db = get_db()
    cursor = db.cursor()

    # Generate date labels
    labels = []
    today = datetime.now().date()
    for i in range(days - 1, -1, -1):
        date = today - timedelta(days=i)
        labels.append(date.strftime('%b %d'))

    # Get received data (simplified for demo)
    received = [random.randint(5, 20) for _ in range(days)]

    # Get transferred data (simplified for demo)
    transferred = [random.randint(2, 15) for _ in range(days)]

    return jsonify({
        'labels': labels,
        'received': received,
        'transferred': transferred
    })


@app.route('/api/dashboard/charts/sales', methods=['GET'])
@login_required
def get_sales_chart_data():
    days = int(request.args.get('days', 7))

    db = get_db()
    cursor = db.cursor()

    # Generate date labels
    labels = []
    today = datetime.now().date()
    for i in range(days - 1, -1, -1):
        date = today - timedelta(days=i)
        labels.append(date.strftime('%b %d'))

    # Get warehouse sales (simplified for demo)
    warehouse_sales = [random.randint(1000, 5000) for _ in range(days)]

    # Get showroom sales (simplified for demo)
    showroom_sales = [random.randint(500, 3000) for _ in range(days)]

    return jsonify({
        'labels': labels,
        'warehouse_sales': warehouse_sales,
        'showroom_sales': showroom_sales
    })


# HTML Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Handle form submission if needed
        pass

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(debug=True)