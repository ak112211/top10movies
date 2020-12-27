import base64
import hashlib
from typing import Any
import os
import flask
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import *
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from flask_sqlalchemy import *
from flask_wtf import Form
from sqlalchemy.exc import InterfaceError, IntegrityError
import bcrypt
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from sqlalchemy.orm import session, sessionmaker
from sqlalchemy.sql.functions import user
from wtforms import StringField, SubmitField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
import requests
from pyramid.view import view_config
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import *
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///movie.db"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "users.login"
login_manager.login_message = u"Bonvolu ensaluti por uzi tiun paĝon."
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"


class LoginForm(Form):
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('password', [validators.Length(min=5)])

class SignUpForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=35)])
    email = EmailField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('password', [validators.Length(min=5)])
    accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(250))

    def __init__(self, username, password, email):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

    def __repr__(self):
        return '<User %r>' % self.username


class Book(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    rating = db.Column(db.Float, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    ranking = db.Column(db.Integer, nullable=False)
    review = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return '<Book %r>' % self.title

db.create_all()

Bootstrap(app)

id = 1
book = Any


@app.route("/")
@login_required
def gotohome():
    userid = current_user.get_id()
    user = User.query.get(userid)
    print(user.email)
    return redirect("/home")


@app.route("/home")
@login_required
def home():
    global book
    userid = current_user.get_id()
    user = User.query.get(userid)
    books = Book.query.filter_by(user=user.username).all()
    print(user.email)
    if current_user.is_authenticated == False:
        return redirect("/login")
    for book in books:
        print(book.title)
    return render_template("index.html", books=books, User=User, current_user=current_user)

@app.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    global book
    global id
    id = request.args['my_var']
    return render_template('edit.html', id=id)


@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    if request.method == 'POST':
        title1 = request.form.get('title')
        id = int(request.args['my_var'])
        book = Book.query.get(id)
        book.title = title1
        print(book.title)
        db.session.commit()
        return redirect("/")


@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'GET':
        id = int(request.args['my_var'])
        book_to_delete = Book.query.get(id)
        db.session.delete(book_to_delete)
        db.session.commit()
        return redirect("/")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():

        # Login and validate the user.
        # user should be an instance of your `User` class
        print(form.email.data)
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                authenticated_user = bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8'))
                if authenticated_user:
                    login_user(user)
                    flask.flash('Logged in successfully.')

                    return flask.redirect(flask.url_for('home'))
        except InterfaceError:
            return "User not authorized" and redirect('/login')

    return flask.render_template('login.html', form=form)

@app.route('/signup', methods =["GET", "POST"])
def signup():
    form = SignUpForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == "POST" and form.validate():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if not user:
               new_user = User(form.username.data , form.email.data , form.password.data)
               db.session.add(new_user)
               db.session.commit()
               login_user(user)
               return redirect(url_for('home'))
            else:
               return redirect(url_for('login'))
        except IntegrityError as e:
            return render_template('signup.html', form=form)
    else:
        return render_template('signup.html', form=form)


@login_required
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/login')


@login_manager.unauthorized_handler
def unauthorized():
    print("Unauthorized")
    return redirect('/login')


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)
