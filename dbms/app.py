from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DATABASE'] = 'todo.db'

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                due_date DATE,
                priority TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        if cursor.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            sample_users = [
                ('admin', generate_password_hash('admin123'), 'admin@example.com'),
                ('user1', generate_password_hash('password1'), 'user1@example.com'),
                ('user2', generate_password_hash('password2'), 'user2@example.com')
            ]
            cursor.executemany('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', sample_users)
            
            sample_todos = [
                (1, 'Complete project', 'Finish the Flask todo app', 'pending', '2023-12-31', 'high', None),
                (1, 'Buy groceries', 'Milk, eggs, bread', 'completed', '2023-11-15', 'medium', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                (2, 'Learn Flask', 'Study Flask documentation', 'in-progress', '2023-11-30', 'high', None),
                (3, 'Exercise', 'Go for a run', 'pending', None, 'low', None)
            ]
            cursor.executemany('''
                INSERT INTO todos (user_id, title, description, status, due_date, priority, completed_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', sample_todos)
        conn.commit()

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        try:
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO users (username, password, email) 
                    VALUES (?, ?, ?)
                ''', (username, generate_password_hash(password), email))
                conn.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def user_dashboard():
    user_id = session['user_id']
    
    with get_db() as conn:
        status_counts = conn.execute('''
            SELECT status, COUNT(*) as count 
            FROM todos 
            WHERE user_id = ? 
            GROUP BY status
        ''', (user_id,)).fetchall()
        
        recent_todos = conn.execute('''
            SELECT * FROM todos 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 5
        ''', (user_id,)).fetchall()
        
        high_priority = conn.execute('''
            SELECT * FROM todos 
            WHERE user_id = ? AND priority = 'high' AND status != 'completed'
            ORDER BY due_date ASC
            LIMIT 5
        ''', (user_id,)).fetchall()
    
    return render_template('dashboard.html',
                         status_counts=status_counts,
                         recent_todos=recent_todos,
                         high_priority=high_priority)

@app.route('/todos/list')
@login_required
def list_todos():
    user_id = session['user_id']
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    
    query = 'SELECT * FROM todos WHERE user_id = ?'
    params = [user_id]
    
    if status_filter != 'all':
        query += ' AND status = ?'
        params.append(status_filter)
    
    if priority_filter != 'all':
        query += ' AND priority = ?'
        params.append(priority_filter)
    
    query += ' ORDER BY due_date ASC, priority DESC'
    
    with get_db() as conn:
        todos = conn.execute(query, tuple(params)).fetchall()
    
    return render_template('todos.html', todos=todos)

@app.route('/todos/add', methods=['GET', 'POST'])
@login_required
def add_todo():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']
        due_date = request.form['due_date'] or None
        priority = request.form['priority']
        
        if not title:
            flash('Title is required', 'danger')
        else:
            with get_db() as conn:
                conn.execute('''
                    INSERT INTO todos (user_id, title, description, status, due_date, priority)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session['user_id'], title, description, status, due_date, priority))
                conn.commit()
            
            flash('Todo added successfully', 'success')
            return redirect(url_for('list_todos'))
    
    return render_template('create_task_todo.html', datetime=datetime)

@app.route('/todos/<int:todo_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_todo(todo_id):
    with get_db() as conn:
        todo = conn.execute('''
            SELECT * FROM todos 
            WHERE id = ? AND user_id = ?
        ''', (todo_id, session['user_id'])).fetchone()
        
        if not todo:
            flash('Todo not found', 'danger')
            return redirect(url_for('list_todos'))
        
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            status = request.form['status']
            due_date = request.form['due_date'] or None
            priority = request.form['priority']
            
            completed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if status == 'completed' else None
            
            if not title:
                flash('Title is required', 'danger')
            else:
                conn.execute('''
                    UPDATE todos 
                    SET title = ?, 
                        description = ?, 
                        status = ?, 
                        due_date = ?, 
                        priority = ?,
                        completed_at = ?
                    WHERE id = ? AND user_id = ?
                ''', (title, description, status, due_date, priority, completed_at, todo_id, session['user_id']))
                conn.commit()
                flash('Todo updated successfully', 'success')
                return redirect(url_for('list_todos'))
    
    return render_template('edit_todo.html', todo=todo)

@app.route('/todos/<int:todo_id>/delete', methods=['POST'])
@login_required
def delete_todo(todo_id):
    with get_db() as conn:
        conn.execute('''
            DELETE FROM todos 
            WHERE id = ? AND user_id = ?
        ''', (todo_id, session['user_id']))
        conn.commit()
    
    flash('Todo deleted successfully', 'success')
    return redirect(url_for('list_todos'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/todos/completed')
@login_required
def completed_todos():
    user_id = session['user_id']
    with get_db() as conn:
        completed_todos = conn.execute('''
            SELECT * FROM todos 
            WHERE user_id = ? AND status = 'completed'
            ORDER BY completed_at DESC
        ''', (user_id,)).fetchall()
    return render_template('completed_todo.html', completed_todos=completed_todos)

@app.route('/todos/<int:todo_id>/reopen', methods=['POST'])
@login_required
def reopen_todo(todo_id):
    with get_db() as conn:
        conn.execute('''
            UPDATE todos 
            SET status = 'pending', completed_at = NULL
            WHERE id = ? AND user_id = ?
        ''', (todo_id, session['user_id']))
        conn.commit()
    flash('Task reopened successfully', 'success')
    return redirect(url_for('completed_todos'))

@app.route('/todos/clear-completed', methods=['POST'])
@login_required
def clear_completed():
    user_id = session['user_id']
    with get_db() as conn:
        conn.execute('''
            DELETE FROM todos 
            WHERE user_id = ? AND status = 'completed'
        ''', (user_id,))
        conn.commit()
    flash('All completed tasks have been cleared', 'success')
    return redirect(url_for('completed_todos'))

@app.route('/todos/<int:todo_id>/confirm-delete')
@login_required
def confirm_delete(todo_id):
    with get_db() as conn:
        todo = conn.execute('''
            SELECT * FROM todos 
            WHERE id = ? AND user_id = ?
        ''', (todo_id, session['user_id'])).fetchone()
        
    if not todo:
        flash('Todo not found', 'danger')
        return redirect(url_for('list_todos'))
    
    return render_template('delete_todo.html', todo=todo)

@app.route('/todos/new')
@login_required
def new_todos():
    user_id = session['user_id']
    with get_db() as conn:
        todos = conn.execute('''
            SELECT *, 
            DATE(due_date) as due_date,
            JULIANDAY(due_date) - JULIANDAY('now') as days_left
            FROM todos 
            WHERE user_id = ? AND status = 'pending'
            ORDER BY 
                CASE priority
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                END,
                due_date ASC
        ''', (user_id,)).fetchall()
    return render_template('new_tasks_todo.html', todos=todos)

@app.route('/todos/<int:todo_id>/start', methods=['POST'])
@login_required
def start_todo(todo_id):
    with get_db() as conn:
        conn.execute('''
            UPDATE todos 
            SET status = 'in-progress'
            WHERE id = ? AND user_id = ?
        ''', (todo_id, session['user_id']))
        conn.commit()
    flash('Task marked as in progress', 'success')
    return redirect(url_for('new_todos'))

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    with get_db() as conn:
        user = conn.execute('SELECT username, email FROM users WHERE id = ?', (user_id,)).fetchone()
        completed_count = conn.execute('SELECT COUNT(*) FROM todos WHERE user_id = ? AND status = "completed"', (user_id,)).fetchone()[0]
        pending_count = conn.execute('SELECT COUNT(*) FROM todos WHERE user_id = ? AND status != "completed"', (user_id,)).fetchone()[0]
    
    return render_template('profile.html', 
                         username=user['username'],
                         email=user['email'],
                         completed=completed_count,
                         pending=pending_count)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)