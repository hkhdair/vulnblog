"""
VulnBlog - A deliberately vulnerable blog application for security education
WARNING: This application contains security vulnerabilities for educational purposes only!
"""

from flask import Flask, render_template, request, redirect, session, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime
import hashlib
import os
import pickle
import subprocess

app = Flask(__name__)
app.secret_key = 'super-secret-key-123'
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(32), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default admin user if not exists
    admin = User.query.filter_by(email='admin@vulnblog.com').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@vulnblog.com',
            password=hashlib.md5('admin123'.encode()).hexdigest(),
            is_admin=True
        )
        db.session.add(admin)
        
    # Create default regular user
    user = User.query.filter_by(email='user@example.com').first()
    if not user:
        user = User(
            username='user',
            email='user@example.com',
            password=hashlib.md5('password123'.encode()).hexdigest(),
            is_admin=False
        )
        db.session.add(user)
        
    db.session.commit()

@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        return redirect('/login')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        query = f"SELECT * FROM user WHERE email = '{email}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"
        result = db.session.execute(text(query))
        user = result.fetchone()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[4]
            resp = make_response(redirect('/'))
            resp.set_cookie('user_data', f'{user[0]}|{user[1]}|{user[4]}')
            return resp
        else:
            return render_template('login.html', error='Invalid email or password. SQL Query: ' + query)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/'))
    resp.set_cookie('user_data', '', expires=0)
    return resp

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        user_id = session.get('user_id', 1)
        user_id = session.get('user_id', 1)
        
        post = Post(title=title, content=content, user_id=user_id)
        db.session.add(post)
        db.session.commit()
        
        return redirect('/')
    
    return render_template('create_post.html')

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template('post.html', post=post, comments=comments)

@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    content = request.form['content']
    user_id = session.get('user_id', 1)
    
    comment = Comment(content=content, user_id=user_id, post_id=post_id)
    db.session.add(comment)
    db.session.commit()
    
    return redirect(f'/post/{post_id}')

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get(user_id)
    posts = Post.query.filter_by(user_id=user_id).all()
    return render_template('profile.html', user=user, posts=posts)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    sql = f"SELECT * FROM post WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
    results = db.session.execute(text(sql)).fetchall()
    
    posts = []
    for result in results:
        posts.append({
            'id': result[0],
            'title': result[1],
            'content': result[2],
            'created_at': result[3]
        })
    
    return render_template('search.html', posts=posts, query=query)

@app.route('/admin')
def admin():
    # VULNERABILITY: Weak authorization check
    if session.get('is_admin'):
        users = User.query.all()
        current_date = datetime.now().strftime('%Y%m%d')
        return render_template('admin.html', users=users, current_date=current_date)
    else:
        return 'Access Denied', 403

@app.route('/admin/backup')
def backup():
    backup_name = request.args.get('name', 'backup')
    cmd = f"tar -czf backups/{backup_name}.tar.gz vulnblog.db"
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    return f"Backup created: {backup_name}.tar.gz<br>Command output: {result.stdout}"

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    user = User.query.get(user_id)
    if user:
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password_hash': user.password,  # Exposing password hash!
            'is_admin': user.is_admin
        }
    return {'error': 'User not found'}, 404

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = file.filename
            file.save(os.path.join('static/uploads', filename))
            return f'File uploaded: <a href="/static/uploads/{filename}">{filename}</a>'
    
    return render_template('upload.html')

@app.route('/debug')
def debug():
    data = request.args.get('data', '')
    if data:
        try:
            obj = pickle.loads(eval(data))
            return f'Deserialized object: {obj}'
        except:
            return 'Error deserializing data'
    
    return '''
    <h1>Debug Console</h1>
    <p>Application Variables:</p>
    <pre>
    SECRET_KEY: {0}
    DATABASE: {1}
    DEBUG MODE: {2}
    </pre>
    '''.format(app.secret_key, app.config['SQLALCHEMY_DATABASE_URI'], app.config['DEBUG'])

@app.errorhandler(404)
def not_found(e):
    return f'Page not found: {request.url}<br>Error: {str(e)}', 404

@app.errorhandler(500)
def server_error(e):
    import traceback
    return f'<pre>Server Error:\n{traceback.format_exc()}</pre>', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)