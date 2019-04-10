from app import app
from flask import render_template,flash
from functools import wraps
from app import app, db
from app.forms import LoginForm, RegistrationForm
from flask import render_template, redirect, url_for
from flask_login import current_user, login_user, login_required, logout_user
from app.models import User
from werkzeug.security import generate_password_hash, check_password_hash

def level_required(level):
    
	def level_required_wrap(func):    
		@wraps(func)
		def d_view(*args, **kwargs):
			try:
				if current_user.super():
					print("Super user. Yeah!")
					return func(*args, **kwargs)
				elif current_user.level == 0:
					print("Level 0 user")
					return redirect(url_for('home'))
				elif current_user.level == 1:
					print("Level 1 user")
					return redirect(url_for('home'))
				else:
					print("Unauthorized")
					return redirect(url_for('unauthorized'))
            
			except Exception as e:
				print("Exception occured", e)
				return redirect(url_for('unauthorized'))
			return func(*args, **kwargs)

		return d_view

	return level_required_wrap

@app.route("/")
@login_required
def home():
	return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('hello'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data.lower()).first()
		if user is None or not user.check_password(form.password.data):
			flash('Invalid username or password')
			return redirect(url_for('login'))
		login_user(user)
		return redirect(url_for('home'))
	return render_template('login.html', form=form, title="Login")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
    	user = User(roll=form.roll.data.lower(), email=form.email.data.lower(), fname=form.fname.data, lname=form.lname.data)
    	user.set_password(form.password.data)
    	db.session.add(user)
    	db.session.commit()
    	flash('Congratulations, you are now a registered user!')
    	return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
def logout():
 	logout_user()
 	return redirect(url_for('home'))
