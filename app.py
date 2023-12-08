import sqlite3
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from flask_wtf.file import FileRequired, FileAllowed
from wtforms.validators import InputRequired, Length
from werkzeug.utils import secure_filename

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv('.env')

bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static/images')

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

file_extension = ['jpg', 'jpe', 'jpeg', 'png', 'gif', 'svg', 'bmp']


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)


class Image(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    filename = db.Column(db.String(20), nullable=False, unique=True)
    uploader = db.Column(db.String(20), nullable=False)

    def __init__(self, filename, uploader):
        self.filename = filename
        self.uploader = uploader


class Following(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    following = db.Column(db.String(100000))
    uploads = db.Column(db.String(100000))
    followers = db.Column(db.String(100000))
    following_count = db.Column(db.Integer)
    uploads_count = db.Column(db.Integer)
    followers_count = db.Column(db.Integer)

    def __init__(self, username):
        self.username = username
        self.following = '-1'
        self.followers = '-1'
        self.uploads = '-1'
        self.followers_count = 0
        self.following_count = 0
        self.uploads_count = 0

    def add_following(self, username):
        self.following += "/" + str(username)
        self.following_count += 1
        db.session.commit()
        user_followed = Following.query.filter_by(username=username).first()
        user_followed.add_followers(self.username)

    def remove_following(self, username):
        following_list = self.following.split("/")
        following_list.remove(username)
        self.following_count -= 1
        self.following = "/".join(following_list)
        db.session.commit()
        user_followed = Following.query.filter_by(username=username).first()
        user_followed.remove_follower(self.username)

    def get_following(self):
        return self.following.split("/")[1::]

    def add_followers(self, username):
        self.followers += "/" + str(username)
        self.followers_count += 1
        db.session.commit()

    def remove_follower(self, username):
        follower_list = self.followers.split("/")
        follower_list.remove(username)
        print(follower_list)
        self.followers_count -= 1
        self.followers = "/".join(follower_list)
        db.session.commit()

    def get_followers(self):
        return self.followers.split("/")[1::]

    def add_image(self, name):
        self.uploads += "/" + str(name)
        self.uploads_count += 1
        db.session.commit()

    def get_images(self):
        return self.uploads.split("/")[1::]


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)],
                             render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def __int__(self, username, password):
        self.username = username
        self.password = password

    def validate_username(self, username):
        uname = str(username.data).lower()
        existing_user_username = User.query.filter_by(username=uname).first()
        if existing_user_username:
            return True


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=32)],
                             render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class SearchForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField('Submit')


class UploadForm(FlaskForm):
    photo = FileField(validators=[FileAllowed(file_extension, 'Image only!'),
                                  FileRequired('File was empty!')])
    submit = SubmitField('Upload')


@app.route('/')
def home():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    posts = []
    for file in files:
        user = Image.query.filter_by(filename=file).first()
        if user:
            username = user.uploader
            posts.append([file, username])
    return render_template('home.html', posts=posts)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.lower()).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('profile'))
            else:
                return render_template('login.html', form=form, error=True)
        else:
            return render_template('login.html', form=form, error=True)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    try:
        if form.validate_username(form.username):
            return render_template('register.html', form=form, error=True)
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data.lower(), password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            new_Fuser = Following(form.username.data.lower())
            db.session.add(new_Fuser)
            db.session.commit()

            return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        return render_template('register.html', form=form, error=True)

    return render_template('register.html', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = current_user.username
    user = Following.query.filter_by(username=username).first()
    posts = user.get_images()

    return render_template('loggedin/profile.html', user=user, posts=posts)


@app.route('/<username>', methods=['GET', 'POST'])
@login_required
def user_profile(username):
    print(username)
    user = Following.query.filter_by(username=username).first()
    if user:
        posts = user.get_images()
        current_user_is = Following.query.filter_by(username=current_user.username).first()
        current_user_following = current_user_is.get_following()
        if user.username in current_user_following:
            return render_template('loggedin/profile.html', user=user, posts=posts,
                                   follow_button=True, following_user=True)
        else:
            return render_template('loggedin/profile.html', user=user, posts=posts,
                                   follow_button=True, following_user=False)
    else:
        return redirect(url_for('search'))


@app.route('/<username>/following')
@login_required
def following_page(username):
    user = Following.query.filter_by(username=username).first()
    if user:
        posts = user.get_images()
        return render_template('loggedin/following.html', user=user, posts=posts)

    else:
        return render_template('loggedin/following.html', error=True)


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    form = SearchForm()
    if form.validate_on_submit():
        username = form.username.data.lower()
        user = Following.query.filter_by(username=username).first()
        if user:
            print(username)
            print(current_user.username)
            if username == current_user.username:
                return redirect(url_for('profile'))
            else:
                return redirect(url_for('user_profile', username=username))

        else:
            return render_template('loggedin/search.html', error=True, form=form)

    return render_template('loggedin/search.html', form=form)


@login_required
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        filename = secure_filename(form.photo.data.filename).split('.')[-1]
        amount = len(os.listdir(app.config['UPLOAD_FOLDER']))
        new_filename = f'{amount}.{filename}'
        form.photo.data.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
        username = current_user.username
        user = Following.query.filter_by(username=username).first()
        user.add_image(new_filename)
        file = Image(new_filename, username)
        db.session.add(file)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('loggedin/upload.html', form=form)


@app.route('/<username>/follow')
@login_required
def follow_user(username):
    user = Following.query.filter_by(username=username).first()
    if user:
        current_user_is = Following.query.filter_by(username=current_user.username).first()
        current_user_following = current_user_is.get_following()
        if user.username not in current_user_following:
            current_user_is.add_following(user.username)

        return redirect(url_for('user_profile', username=user.username))

    else:
        return redirect(url_for('profile'))


@app.route('/<username>/unfollow')
@login_required
def unfollow_user(username):
    user = Following.query.filter_by(username=username).first()
    if user:
        current_user_is = Following.query.filter_by(username=current_user.username).first()
        current_user_following = current_user_is.get_following()
        if user.username in current_user_following:
            current_user_is.remove_following(user.username)

        return redirect(url_for('user_profile', username=user.username))

    else:
        return redirect(url_for('profile'))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
