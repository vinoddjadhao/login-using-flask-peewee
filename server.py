from flask import render_template, redirect, url_for, request, flash, Flask
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, LoginManager, current_user
from flask_login import UserMixin
from peewee import *
from flask_peewee.db import Database

app = Flask(__name__)

app.config['SECRET_KEY'] = 'temp-key'
dbhandle = MySQLDatabase('db_name', user = 'admin', password = 'admin', host = 'localhost')

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))

class User(UserMixin, Model):
    id = PrimaryKeyField(null=False)
    email = CharField(max_length=100)
    password = CharField(max_length=100)
    name = CharField(max_length=100)

    class Meta:
        database = dbhandle

try:
    dbhandle.connect()
    User.create_table()
except InternalError as px:
    print(str(px))

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    user_exist = True
    uemail = request.form.get('email')
    upassword = request.form.get('password')
    remember = True if request.form.get('remember') else False

    try:
        user = User.select().where(User.email==uemail).get()
    except DoesNotExist:
        user_exist = False

    if not user_exist or not check_password_hash(user.password, upassword): 
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) 

    login_user(user, remember=remember)
    return redirect(url_for('profile'))

@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    user_exist = True

    uemail = request.form.get('email')
    uname = request.form.get('name')
    upassword = request.form.get('password')

    try:
        User.select().where(User.email==uemail).get()
    except DoesNotExist:
        user_exist = False
    
    if user_exist: 
        flash('Email address already exists')
        return redirect(url_for('signup'))

    new_user = User.create(email=uemail, name=uname, password=generate_password_hash(upassword, method='sha256'))

    new_user.save()

    return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)
