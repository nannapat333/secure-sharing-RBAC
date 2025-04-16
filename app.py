import os
import uuid
import json
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from models import db, User, File
from utils.encryption import (
    generate_rsa_key_pair, generate_aes_key,
    encrypt_file, decrypt_file,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
)

app = Flask(__name__)
os.makedirs("instance", exist_ok=True)
os.makedirs("uploads", exist_ok=True)

app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.abspath('instance/manual.db')}"
print("Final DB Path:", app.config['SQLALCHEMY_DATABASE_URI'])
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

ROLE_PERMISSIONS = {
    'admin': ['upload', 'download', 'delete', 'share'],
    'uploader': ['upload', 'download'],
    'viewer': ['download'],
    'guest': ['download']
}

def is_allowed(action):
    return action in ROLE_PERMISSIONS.get(current_user.role, [])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        public_key, private_key = generate_rsa_key_pair()
        new_user = User(username=username, password=password, role=role,
                        rsa_public_key=public_key, rsa_private_key=private_key)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        # 🔍 Debug prints
        print("Login attempt → Username:", username)
        print("User found?" , bool(user))
        if user:
            print("Password match:", check_password_hash(user.password, password))
        else:
            print("User not found in database")

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        files = File.query.all()
    else:
        files = File.query.filter(
            or_(File.owner_id == current_user.id,
                File.shared_with.contains(str(current_user.id)))
        ).all()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not is_allowed('upload'):
        return "Access denied", 403
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if not uploaded_file:
            flash("No file selected")
            return redirect(request.url)
        aes_key = generate_aes_key()
        encrypted_data = encrypt_file(uploaded_file.read(), aes_key)
        file_id = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        selected_options = request.form.getlist('share_with')
        shared_user_ids = {current_user.id}
        user_keys = {}

        # Automatically include admin in shared users
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user:
            shared_user_ids.add(admin_user.id)

        for option in selected_options:
            if option.startswith("user:"):
                shared_user_ids.add(int(option.split(":")[1]))
            elif option.startswith("role:"):
                users_with_role = User.query.filter_by(role=option.split(":")[1]).all()
                for u in users_with_role:
                    shared_user_ids.add(u.id)
        for uid in shared_user_ids:
            user = User.query.get(uid)
            encrypted_key = encrypt_aes_key_with_rsa(aes_key, user.rsa_public_key)
            user_keys[str(uid)] = encrypted_key.hex()
        new_file = File(filename=uploaded_file.filename,
                        owner_id=current_user.id,
                        encrypted_keys=json.dumps(user_keys),
                        file_path=file_path,
                        shared_with=",".join(str(uid) for uid in shared_user_ids))
        db.session.add(new_file)
        db.session.commit()
        flash("File uploaded and shared successfully")
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('upload.html', users=users)

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if current_user.role != 'admin' and str(current_user.id) not in file.shared_with.split(','):
        return "Unauthorized", 403
    if current_user.role == 'guest':
        return "Not permitted — Guests can only view files.", 403
    try:
        encrypted_data = open(file.file_path, 'rb').read()
        encrypted_key_hex = file.get_encrypted_key_for_user(current_user.id)

        if not encrypted_key_hex:
            return "Access denied: You were not granted a decryption key for this file.", 403

        try:
            aes_key = decrypt_aes_key_with_rsa(bytes.fromhex(encrypted_key_hex), current_user.rsa_private_key)
        except Exception as e:
            return f"Decryption failed: {str(e)}", 403

        decrypted_data = decrypt_file(encrypted_data, aes_key)
        temp_path = f"temp_{file.filename}"
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)
        return send_file(temp_path, as_attachment=True, download_name=file.filename)
    except Exception as e:
        return f"Error decrypting: {str(e)}", 403

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    if not is_allowed('delete'):
        return "Access denied", 403
    file = File.query.get_or_404(file_id)
    try:
        os.remove(file.file_path)
    except Exception:
        pass
    db.session.delete(file)
    db.session.commit()
    flash("File deleted.")
    return redirect(url_for('dashboard'))

@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    file = File.query.get_or_404(file_id)
    if current_user.role != 'admin' and str(current_user.id) not in file.shared_with.split(','):
        return "Unauthorized", 403

    try:
        encrypted_data = open(file.file_path, 'rb').read()
        encrypted_key_hex = file.get_encrypted_key_for_user(current_user.id)

        if not encrypted_key_hex:
            return "Access denied: You were not granted a decryption key for this file.", 403

        try:
            aes_key = decrypt_aes_key_with_rsa(bytes.fromhex(encrypted_key_hex), current_user.rsa_private_key)
        except Exception as e:
            return f"Decryption failed: {str(e)}", 403

        decrypted_data = decrypt_file(encrypted_data, aes_key)
        ext = os.path.splitext(file.filename)[1].lower()
        content, file_url = None, None
        is_image = is_pdf = False
        if ext in ['.txt', '.csv', '.py']:
            content = decrypted_data.decode(errors="ignore")
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            temp_path = f"static/temp_{file.filename}"
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
            file_url = '/' + temp_path
            is_image = True
        elif ext == '.pdf':
            temp_path = f"static/temp_{file.filename}"
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
            file_url = '/' + temp_path
            is_pdf = True
        return render_template('view_file.html', file=file, file_content=content,
                               file_url=file_url, is_image=is_image, is_pdf=is_pdf)
    except Exception as e:
        return f"Error viewing file: {str(e)}", 403

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        from werkzeug.security import generate_password_hash
        from utils.encryption import generate_rsa_key_pair

        # Delete the old admin user if it exists
        existing_admin = User.query.filter_by(username='admin').first()
        if existing_admin:
            db.session.delete(existing_admin)
            db.session.commit()

        # Recreate admin
        public_key, private_key = generate_rsa_key_pair()
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='admin',
            rsa_public_key=public_key,
            rsa_private_key=private_key
        )
        db.session.add(admin)
        db.session.commit()

        print("Fresh admin created: admin / admin123")

    app.run(host='0.0.0.0', port=5050, debug=True)
