from app import app
from flask import render_template,flash
from functools import wraps
from app import app, db
from app.forms import LoginForm, RegistrationForm, AddForm
from flask import render_template, redirect, url_for
from flask_login import current_user, login_user, login_required, logout_user
from app.models import User, Courier
from app.mail import email_new
from werkzeug.security import generate_password_hash, check_password_hash
import math, random

def level_required(level):
	def level_required_wrap(func):    
		@wraps(func)
		def d_view(*args, **kwargs):
			try:
				if current_user.level >= level:
					return func(*args, **kwargs)
			except Exception as e:
				print("Exception occured", e)
				return redirect(url_for('unauthorized'))
			return redirect(url_for('unauthorized'))
		return d_view
	return level_required_wrap

def generateOTP():
	string = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	OTP = "" 
	length = len(string)
	for i in range(6):
		OTP += string[math.floor(random.random() * length)] 
	return OTP 

@app.route("/unauthorized")
def unauthorized():
	return "You are not nauthorized for this operation"

@app.route("/")
@login_required
def home():
	if current_user.level >= 1:
		#Code for fetching data for the admin dashboard
		return render_template('admin.html', user=current_user)
	
	elif current_user.level == 0:
		#code for fetching data for the user dashboard 
		return render_template('user.html', user=current_user)
	
	return "403 Error Occurred"

@app.route("/login", methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
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

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
@level_required(1)
def add():
	form = AddForm()
	if form.validate_on_submit():
		user = User.query.filter_by(roll=form.roll.data.lower()).first()
		key = generateOTP()
		courier = Courier(title=form.title.data, recv=user.id, verify_key=key, tracking_id=form.tracking_id.data)
		db.session.add(courier)
		db.session.commit()
		email_new(user,courier)
		flash('Successfully Added')
		return redirect(url_for('home'))
	return render_template('add.html', title='Add', form=form)

@app.route('/admin/uncollected')
@login_required
@level_required(1)
def uncollected_admin():
	couriers = db.session.query(Courier,User).filter(Courier.recv==User.id and Courier.collected==False).all()
	return render_template('uncollected_admin.html', title='Uncollected', couriers=couriers)

@app.route('/admin/collected')
@login_required
@level_required(1)
def collected_admin():
	couriers = db.session.query(Courier,User).filter(Courier.recv==User.id and Courier.collected==True).all()
	return render_template('collected_admin.html', title='Collected', couriers=couriers)