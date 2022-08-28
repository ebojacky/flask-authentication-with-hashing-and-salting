from flask import Flask, render_template, request, url_for, redirect, send_from_directory, flash
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

login_manager = LoginManager()

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()

# This part is needed for Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routing Starts Here
@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_in_db = User.query.filter_by(email=request.form.get("email")).first()

        if user_in_db is not None:
            flash('Email already exist: login instead!')
            return redirect(url_for("login"))

        new_user = User()
        new_user.name = request.form.get("name")
        new_user.email = request.form.get("email")

        new_user.password = generate_password_hash(
            request.form.get("password"),
            method='pbkdf2:sha256',
            salt_length=8)

        db.session.add(new_user)
        db.session.commit()

        # login user using flask framework
        login_user(new_user)

        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_in_db = User.query.filter_by(email=request.form.get("email")).first()

        if user_in_db is not None and \
                check_password_hash(user_in_db.password, request.form.get("password")):
            login_user(user_in_db)
            return redirect(url_for("secrets"))
        else:
            flash('Invalid Username or Password')

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", logged_in=current_user.is_authenticated, Name=current_user.name)


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
