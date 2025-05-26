from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
import psycopg2
from datetime import datetime
import os
from psycopg2 import OperationalError
from contextlib import closing
from werkzeug.utils import secure_filename
import uuid
import filetype as h

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev_secret_key'  # Replace in production

# Database configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'database': os.environ.get('DB_NAME', 'company_login_system'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', 'tiger'),
    'port': os.environ.get('DB_PORT', '5432')
}

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

def get_db_connection():
    for attempt in range(3):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.autocommit = False
            return conn
        except OperationalError as e:
            if attempt == 2:
                app.logger.error(f"Database connection failed: {e}")
                raise
    return None

def is_admin(userid):
    return userid and 'admin' in userid.lower()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = h.what(None, header)
    return '.' + (format if format != 'jpeg' else 'jpg') if format else None

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    if '..' in filename or filename.startswith('/'):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def home():
    if 'userid' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    if 'userid' in session:
        return redirect(url_for('dashboard'))

    userid = request.form.get('userid', '').strip()
    password = request.form.get('password', '').strip()

    if not userid or not password:
        flash('User ID and password are required', 'error')
        return redirect(url_for('home'))

    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT password FROM credentials WHERE userid = %s", (userid,))
            result = cur.fetchone()
            if result is None or result[0] != password:
                flash('Invalid User ID or Password', 'error')
                return redirect(url_for('home'))

            session['userid'] = userid
            session['is_admin'] = is_admin(userid)

            login_time = datetime.now()
            cur.execute("INSERT INTO login_details (userid, login_time) VALUES (%s, %s) RETURNING id", (userid, login_time))
            login_record = cur.fetchone()
            session['login_id'] = login_record[0] if login_record else None
            conn.commit()

            return redirect(url_for('dashboard'))

    except Exception as e:
        app.logger.error(f"Login error for user {userid}: {str(e)}")
        flash('An error occurred during login. Please try again.', 'error')
        return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'userid' not in session:
        return redirect(url_for('home'))

    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("""
                SELECT login_time, logout_time 
                FROM login_details 
                WHERE userid = %s 
                ORDER BY login_time DESC 
                LIMIT 5
            """, (session['userid'],))
            login_history = cur.fetchall()

        return render_template(
            'dashboard.html',
            userid=session['userid'],
            login_history=login_history,
            is_admin=session.get('is_admin', False)
        )
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('home'))

@app.route('/profile')
def profile():
    if 'userid' not in session:
        flash("Session expired or unauthorized access. Please log in.", "error")
        app.logger.warning("Profile access attempted without login.")
        return redirect(url_for('home'))

    userid = session['userid']
    app.logger.info(f"User '{userid}' accessing profile.")

    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("""
                SELECT profile_pic, full_name 
                FROM user_profiles 
                WHERE userid = %s
            """, (userid,))
            profile_data = cur.fetchone() or (None, userid)

            cur.execute("""
                SELECT activity_type, activity_data, created_at 
                FROM user_activities 
                WHERE userid = %s 
                ORDER BY created_at DESC 
                LIMIT 20
            """, (userid,))
            activities = cur.fetchall()

        template = 'admin_profile.html' if session.get('is_admin') else 'user_profile.html'

        flash("Welcome to your profile page!", "info")
        return render_template(template,
                               profile_pic=profile_data[0],
                               username=profile_data[1],
                               activities=activities,
                               is_admin=session.get('is_admin', False))

    except Exception as e:
        app.logger.error(f"Profile error for user {userid}: {str(e)}")
        flash('Error loading profile', 'error')
        return redirect(url_for('dashboard'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'userid' not in session:
        return redirect(url_for('home'))

    userid = session['userid']
    full_name = request.form.get('full_name', userid)
    profile_pic = None

    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('Invalid file type', 'error')
                return redirect(url_for('profile'))

            file_ext = validate_image(file.stream)
            if file_ext and file_ext[1:] not in ALLOWED_EXTENSIONS:
                flash('Invalid image file', 'error')
                return redirect(url_for('profile'))

            filename = secure_filename(f"{userid}_{uuid.uuid4().hex[:8]}{file_ext}")
            path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics')
            os.makedirs(path, exist_ok=True)
            file.save(os.path.join(path, filename))
            profile_pic = f"uploads/profile_pics/{filename}"

    try:
        with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
            cur.execute("""
                INSERT INTO user_profiles (userid, full_name, profile_pic)
                VALUES (%s, %s, %s)
                ON CONFLICT (userid)
                DO UPDATE SET full_name = EXCLUDED.full_name,
                              profile_pic = COALESCE(EXCLUDED.profile_pic, user_profiles.profile_pic)
            """, (userid, full_name, profile_pic))
            conn.commit()
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Profile update error: {str(e)}")
        flash('Error updating profile', 'error')

    return redirect(url_for('profile'))

@app.route('/admin_upload', methods=['POST'])
def admin_upload():
    if 'userid' not in session or not session.get('is_admin'):
        flash('Admin access required', 'error')
        return redirect(url_for('home'))

    if 'content' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('profile'))

    file = request.files['content']
    caption = request.form.get('caption', '')

    if file and file.filename:
        if not allowed_file(file.filename):
            flash('Invalid file type', 'error')
            return redirect(url_for('profile'))

        file_ext = file.filename.rsplit('.', 1)[1].lower()
        if file_ext in {'jpg', 'jpeg', 'png', 'gif'}:
            if not validate_image(file.stream):
                flash('Invalid image file', 'error')
                return redirect(url_for('profile'))

        filename = secure_filename(f"post_{uuid.uuid4().hex[:8]}.{file_ext}")
        path = os.path.join(app.config['UPLOAD_FOLDER'], 'posts')
        os.makedirs(path, exist_ok=True)
        file.save(os.path.join(path, filename))

        try:
            with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
                cur.execute("""
                    INSERT INTO admin_posts (admin_id, file_path, caption)
                    VALUES (%s, %s, %s)
                """, (session['userid'], f"uploads/posts/{filename}", caption))

                cur.execute("SELECT userid FROM credentials")
                for (userid,) in cur.fetchall():
                    cur.execute("""
                        INSERT INTO notifications (userid, message, link)
                        VALUES (%s, %s, %s)
                    """, (userid, 'New admin post available', '/profile'))
                conn.commit()

            flash('Post uploaded successfully!', 'success')
        except Exception as e:
            app.logger.error(f"Admin upload error: {str(e)}")
            flash('Error uploading post', 'error')
    else:
        flash('Invalid file', 'error')

    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    if 'userid' in session:
        try:
            with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
                cur.execute("UPDATE login_details SET logout_time = %s WHERE id = %s", (datetime.now(), session.get('login_id')))
                conn.commit()
        except Exception as e:
            app.logger.error(f"Logout error: {str(e)}")
            try:
                conn.rollback()
            except Exception:
                pass
        session.clear()
    return redirect(url_for('home'))

@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        userid = request.form.get('userid', '').strip()
        if not userid:
            flash('User ID is required', 'error')
            return redirect(url_for('forget_password'))

        try:
            with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
                cur.execute("SELECT userid FROM credentials WHERE userid = %s", (userid,))
                if cur.fetchone():
                    return redirect(url_for('reset_password', userid=userid))
                else:
                    flash('User ID not found', 'error')

        except Exception as e:
            app.logger.error(f"Forget password error: {str(e)}")
            flash('An error occurred', 'error')

        return redirect(url_for('forget_password'))

    return render_template('forget_password.html')

@app.route('/reset_password/<userid>', methods=['GET', 'POST'])
def reset_password(userid):
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('reset_password', userid=userid))

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password', userid=userid))

        try:
            with closing(get_db_connection()) as conn, closing(conn.cursor()) as cur:
                cur.execute("UPDATE credentials SET password = %s WHERE userid = %s", (new_password, userid))
                conn.commit()
                flash('Password updated successfully. Please login.', 'info')
                return redirect(url_for('home'))
        except Exception as e:
            app.logger.error(f"Password reset error for {userid}: {str(e)}")
            flash('Error resetting password. Try again.', 'error')

        return redirect(url_for('reset_password', userid=userid))

    return render_template('reset_password.html', userid=userid)

if __name__ == '__main__':
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics'), exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'posts'), exist_ok=True)
    app.run(debug=True)
