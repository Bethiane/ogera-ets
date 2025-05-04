from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config import Config

from decimal import Decimal
app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)

# ======================
#  HELPER FUNCTIONS
# ======================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first!', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Admin check - User ID: {session.get('user_id')}, Admin: {session.get('is_admin')}")
        if 'user_id' not in session:
            flash('Please log in first!', 'danger')
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required!', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ======================
#  AUTHENTICATION ROUTES
# ======================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']  # Get plain text password

        cur = mysql.connection.cursor()
        try:
            # Check if user exists
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if cur.fetchone():
                flash('Username or email already exists!', 'danger')
                return redirect(url_for('register'))

            # First user becomes admin
            cur.execute("SELECT COUNT(*) FROM users")
            count = cur.fetchone()[0]
            is_admin = count == 0

            # Store plain text if admin, hashed otherwise
            password_store = password if is_admin else generate_password_hash(password)

            cur.execute(
                "INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, %s)",
                (username, email, password_store, is_admin)
            )
            mysql.connection.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'danger')
        finally:
            cur.close()
    return render_template('auth/register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password, is_admin FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            # If admin, compare plain text passwords
            if user[2]:  # is_admin is True
                password_valid = (user[1] == password)
            else:
                password_valid = check_password_hash(user[1], password)
            
            if password_valid:
                session['user_id'] = user[0]
                session['is_admin'] = user[2]
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
        
        flash('Invalid credentials!', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/debug_session')
def debug_session():
    return {
        'user_id': session.get('user_id'),
        'is_admin': session.get('is_admin'),
        'is_authenticated': 'user_id' in session
    }

# ======================
#  EXPENSE ROUTES
# ======================

@app.route('/')
@login_required
def index():
    cur = mysql.connection.cursor()
    # Get expenses
    cur.execute("""
        SELECT e.id, e.amount, c.name, e.description, e.date 
        FROM expenses e
        JOIN categories c ON e.category_id = c.id
        WHERE e.user_id = %s 
        ORDER BY e.date DESC
    """, (session['user_id'],))
    expenses = cur.fetchall()

 # Get budget status - ensure Decimal conversion
    cur.execute("""
        SELECT 
            (SELECT amount FROM user_budgets WHERE user_id = %s) as budget,
            COALESCE(SUM(amount), 0) as spent
        FROM expenses 
        WHERE user_id = %s 
        AND MONTH(date) = MONTH(CURDATE())
        AND YEAR(date) = YEAR(CURDATE())
    """, (session['user_id'], session['user_id']))
    
    budget_status = cur.fetchone()

    cur.close()
    
    # Convert to proper numeric types
    current_budget = float(budget_status[0]) if budget_status and budget_status[0] else None
    current_spending = float(budget_status[1]) if budget_status else 0.0
    remaining = float(current_budget - current_spending) if current_budget else None
    percentage = float((current_spending / current_budget * 100)) if current_budget else 0.0
    
    return render_template('index.html',
        expenses=expenses,
        current_budget=current_budget,
        current_spending=current_spending,
        remaining=remaining,
        percentage=percentage
    )


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM categories ORDER BY name")
    categories = cur.fetchall()
    
    if request.method == 'POST':
        try:
            # Convert amount to Decimal immediately
            amount = Decimal(request.form['amount'])
            category_id = request.form['category']
            description = request.form['description']
            date = request.form['date']
            
            # Check budget status (ensure Decimal conversion here too)
            cur.execute("""
                SELECT 
                    (SELECT amount FROM user_budgets WHERE user_id = %s) as budget,
                    COALESCE(SUM(amount), 0) as spent
                FROM expenses 
                WHERE user_id = %s 
                AND MONTH(date) = MONTH(%s)
                AND YEAR(date) = YEAR(%s)
            """, (session['user_id'], session['user_id'], date, date))
            
            budget_data = cur.fetchone()
            warnings = []
            
            if budget_data and budget_data[0]:  # If budget exists
                budget = Decimal(str(budget_data[0]))  # Ensure Decimal
                spent = Decimal(str(budget_data[1] or 0))  # Ensure Decimal
                remaining = budget - spent
                
                # Compare Decimal with Decimal
                if remaining - amount < Decimal('0'):
                    overspend = abs(remaining - amount)
                    warnings.append(
                        f"⚠️ This expense will exceed your budget by {overspend:.2f} RWF"
                        f"({(overspend/budget*100):.0f}% over)"
                    )
                elif (remaining - amount) < budget * Decimal('0.2'):  # Less than 20% remaining
                    warnings.append(
                        f"⚠️ Only {remaining - amount:.2f} RWF remaining in your budget"
                    )
            
            # Add the expense (amount is already Decimal)
            cur.execute(
                "INSERT INTO expenses (amount, category_id, description, date, user_id) VALUES (%s, %s, %s, %s, %s)",
                (str(amount), category_id, description, date, session['user_id'])  # Convert Decimal to string for MySQL
            )
            mysql.connection.commit()
            
            for warning in warnings:
                flash(warning, 'warning')
                
            flash('Expense added successfully!', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error adding expense: {str(e)}', 'danger')
        finally:
            cur.close()
    
    return render_template('add_expense.html', categories=categories)
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM categories ORDER BY name")
    categories = cur.fetchall()
    
    cur.execute("SELECT * FROM expenses WHERE id = %s AND user_id = %s", (id, session['user_id']))
    expense = cur.fetchone()
    
    if request.method == 'POST':
        amount = request.form['amount']
        category_id = request.form['category']
        description = request.form['description']
        date = request.form['date']

        cur.execute(
            "UPDATE expenses SET amount=%s, category_id=%s, description=%s, date=%s WHERE id=%s",
            (amount, category_id, description, date, id)
        )
        mysql.connection.commit()
        flash('Expense updated successfully!', 'success')
        return redirect(url_for('index'))
    
    cur.close()
    return render_template('edit_expense.html', expense=expense, categories=categories)

@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM expenses WHERE id = %s AND user_id = %s", (id, session['user_id']))
    mysql.connection.commit()
    cur.close()
    flash('Expense deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/routes')
def list_routes():
    import urllib.parse
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint:50s} {methods:20s} {rule}")
        output.append(line)
    return '<br>'.join(sorted(output))

# ======================
#  ADMIN ROUTES
# ======================

@app.route('/adminn')
@admin_required
def admin_dashboard():
    try:
        cur = mysql.connection.cursor()
        
        # Get all users
        cur.execute("SELECT id, username, email, is_admin FROM users")
        users = cur.fetchall()
        
        # Get all expenses
        cur.execute("""
            SELECT e.id, e.amount, c.name, e.description, e.date, u.username 
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            JOIN users u ON e.user_id = u.id
""")
        expenses = cur.fetchall()
        
        return render_template('admin/dashboard.html', users=users, expenses=expenses)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('index'))
    finally:
        cur.close()


# Add these new routes after your existing admin routes

@app.route('/admin/categories')
@admin_required
def manage_categories():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM categories ORDER BY name")
    categories = cur.fetchall()
    cur.close()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/categories/add', methods=['GET', 'POST'])
@admin_required
def add_category():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "INSERT INTO categories (name, description) VALUES (%s, %s)",
                (name, description)
            )
            mysql.connection.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('manage_categories'))
        except Exception as e:
            flash(f'Error adding category: {str(e)}', 'danger')
        finally:
            cur.close()
    return render_template('admin/add_category.html')

@app.route('/adminn/categories/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_category(id):
    cur = mysql.connection.cursor()
    
    try:
        # GET request - show edit form
        if request.method == 'GET':
            cur.execute("SELECT * FROM categories WHERE id = %s", (id,))
            category = cur.fetchone()
            
            if not category:
                flash('Category not found!', 'danger')
                return redirect(url_for('manage_categories'))
            
            return render_template('admin/edit_category.html', category=category)
        
        # POST request - process form submission
        elif request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            
            # Update category in database
            cur.execute(
                "UPDATE categories SET name = %s, description = %s WHERE id = %s",
                (name, description, id)
            )
            mysql.connection.commit()
            flash('Category updated successfully!', 'success')
            return redirect(url_for('manage_categories'))
    
    except Exception as e:
        mysql.connection.rollback()
        error_message = str(e)
        
        # Handle duplicate category name
        if "Duplicate entry" in error_message:
            flash('A category with this name already exists!', 'danger')
        else:
            flash(f'Error updating category: {error_message}', 'danger')
        
        # Get current values to repopulate form
        cur.execute("SELECT * FROM categories WHERE id = %s", (id,))
        category = cur.fetchone()
        return render_template('admin/edit_category.html', category=category)
    
    finally:
        cur.close()


@app.route('/adminn/categories/delete/<int:id>')
@admin_required
def delete_category(id):
    cur = mysql.connection.cursor()
    try:
        cur.execute("DELETE FROM categories WHERE id = %s", (id,))
        mysql.connection.commit()
        flash('Category deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting category: {str(e)}', 'danger')
    finally:
        cur.close()
    return redirect(url_for('manage_categories'))

@app.route('/admin/user/delete/<int:id>')
@admin_required
def admin_delete_user(id):
    if id == session['user_id']:
        flash('You cannot delete yourself!', 'danger')
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/expense/delete/<int:id>')
@admin_required
def admin_delete_expense(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM expenses WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    flash('Expense deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# Budget Management Routes
# Budget Management (Single Budget)
@app.route('/budget', methods=['GET', 'POST'])
@login_required
def manage_budget():
    cur = mysql.connection.cursor()
    
    # Get current budget if exists
    cur.execute("SELECT amount FROM user_budgets WHERE user_id = %s", (session['user_id'],))
    current_budget = cur.fetchone()
    
    if request.method == 'POST':
        try:
            # Convert to Decimal immediately
            amount = Decimal(request.form['amount'])
            
            if current_budget:
                # Update existing budget
                cur.execute(
                    "UPDATE user_budgets SET amount = %s WHERE user_id = %s",
                    (str(amount), session['user_id'])  # Convert Decimal to string
                )
            else:
                # Create new budget
                cur.execute(
                    "INSERT INTO user_budgets (user_id, amount) VALUES (%s, %s)",
                    (session['user_id'], str(amount))  # Convert Decimal to string
                )
            mysql.connection.commit()
            flash('Budget updated successfully!', 'success')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error saving budget: {str(e)}', 'danger')
        finally:
            cur.close()
        return redirect(url_for('manage_budget'))
    
    cur.close()
    return render_template('budget.html', 
                         current_budget=Decimal(current_budget[0]) if current_budget else None)
# Budget Deletion
@app.route('/budget/delete', methods=['POST'])
@login_required
def delete_budget():
    cur = mysql.connection.cursor()
    try:
        cur.execute("DELETE FROM user_budgets WHERE user_id = %s", (session['user_id'],))
        mysql.connection.commit()
        flash('Budget deleted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting budget: {str(e)}', 'danger')
    finally:
        cur.close()
    return redirect(url_for('manage_budget'))

@app.route('/check_budget', methods=['POST'])
@login_required
def check_budget():
    data = request.get_json()
    amount = float(data['amount'])
    category_id = data['category_id']
    warnings = []
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            SELECT b.amount, b.period, c.name,
                   COALESCE(SUM(e.amount), 0) as current_spending
            FROM budgets b
            LEFT JOIN categories c ON b.category_id = c.id
            LEFT JOIN expenses e ON e.category_id = b.category_id 
                AND e.user_id = b.user_id
                AND (
                    (b.period = 'weekly' AND YEARWEEK(e.date) = YEARWEEK(CURDATE())) OR
                    (b.period = 'monthly' AND MONTH(e.date) = MONTH(CURDATE())) OR
                    (b.period = 'yearly' AND YEAR(e.date) = YEAR(CURDATE()))
                )
            WHERE b.user_id = %s AND (b.category_id = %s OR b.category_id IS NULL)
            GROUP BY b.id
        """, (session['user_id'], category_id))
        
        budgets = cur.fetchall()
        
        for budget in budgets:
            remaining = budget[0] - budget[3]
            if remaining - amount < 0:
                budget_type = f"for {budget[2]}" if budget[2] else "overall"
                percentage_over = abs((amount - remaining)/budget[0] * 100)
                warnings.append(
                    f"Warning: This would exceed your {budget[1]} {budget_type} budget by {amount - remaining:.2f} RWF ({percentage_over:.0f}%)"
                )
            elif remaining - amount < budget[0] * 0.1:  # Less than 10% remaining
                warnings.append(
                    f"Note: This would leave only {remaining - amount:.2f} RWF in your {budget[1]} {'category' if budget[2] else 'overall'} budget"
                )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
    
    return jsonify({'warnings': warnings})


if __name__ == '__main__':
    app.run(debug=True)