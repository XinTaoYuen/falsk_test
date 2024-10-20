from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# 初始化 Flask 应用
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # 设置 SQLite 数据库文件
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 禁用修改监控
app.secret_key = 'your_secret_key'  # 会话管理密钥

# 初始化数据库
db = SQLAlchemy(app)

# 创建用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# 创建数据库
with app.app_context():
    db.create_all()  # 创建数据库和表

# 主页路由
@app.route('/')
def home():
    return render_template('login.html')

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()  # 查询用户

        if user and check_password_hash(user.password, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# 注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
        else:
            new_user = User(username=username, password=password_hash)
            db.session.add(new_user)  # 将新用户添加到会话
            db.session.commit()  # 提交到数据库
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# 仪表板路由
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f'Welcome, {session["username"]}! <a href="/logout">Logout</a>'
    return redirect(url_for('login'))

# 注销路由
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# 运行应用
if __name__ == '__main__':
    app.run(debug=True)
