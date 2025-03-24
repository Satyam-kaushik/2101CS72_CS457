from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import MySQLdb.cursors

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'role_based_auth'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User Class
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return User(user['id'], user['username'], user['role']) if user else None


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        cursor = mysql.connection.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, 'viewer')", (username, password))
            mysql.connection.commit()
            flash('Account created! Wait for admin to assign role.', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        finally:
            cursor.close()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username'], user['role']))
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid Credentials', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)


@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Unauthorized action! Only admins can access this page.', 'danger')
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM stud_info")
    students = cursor.fetchall()

    cursor.close()
    return render_template('admin.html', users=users, students=students)


@app.route('/assign_role', methods=['POST'])
@login_required
def assign_role():
    if current_user.role != 'admin':
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('dashboard'))

    username = request.form['username']
    role = request.form['role']

    # Ensure only valid roles can be assigned
    if role not in ['admin', 'editor', 'viewer']:
        flash('Invalid role selected!', 'danger')
        return redirect(url_for('admin'))

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("UPDATE users SET role = %s WHERE username = %s", (role, username))
        mysql.connection.commit()
        flash('Role updated!', 'success')
    except Exception as e:
        flash(f'Error updating role: {str(e)}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('admin'))


@app.route('/students')
@login_required
def view_students():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM stud_info")
    students = cursor.fetchall()
    cursor.close()
    return render_template('students.html', students=students)


@app.route('/add_student', methods=['POST'])
@login_required
def add_student():
    if current_user.role not in ['admin', 'editor']:
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('dashboard'))

    roll = request.form['roll']
    name = request.form['name']
    age = request.form['age']
    branch = request.form['branch']
    hometown = request.form['hometown']

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("INSERT INTO stud_info (roll, name, age, branch, hometown) VALUES (%s, %s, %s, %s, %s)",
                       (roll, name, age, branch, hometown))
        mysql.connection.commit()
        flash('Student added!', 'success')
    except Exception as e:
        flash(f'Error adding student: {str(e)}', 'danger')
    finally:
        cursor.close()
    return redirect(url_for('admin'))


@app.route('/delete_student/<string:roll>', methods=['POST'])
@login_required
def delete_student(roll):
    if current_user.role not in ['admin', 'editor']:
        flash('Unauthorized action! Only admins and editors can delete students.', 'danger')
        return redirect(url_for('view_students'))

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM stud_info WHERE roll = %s", (roll,))
        mysql.connection.commit()
        flash('Student deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting student: {str(e)}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('view_students'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized action! Only admins can delete users.', 'danger')
        return redirect(url_for('admin'))

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('admin'))




@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
