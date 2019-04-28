from app import app
from flask import render_template,flash
from functools import wraps
from app import app, db
from app.forms import LoginForm, RegistrationForm, AddForm, MarkCollected, VerifyEmail, AddCodForm
from flask import render_template, redirect, url_for, request
from flask_login import current_user, login_user, login_required, logout_user
from app.models import User, Courier, CourierCod
from app.mail import email_new,email_collected, email_new_user, email_new_cod, email_cod_approved
from werkzeug.security import generate_password_hash, check_password_hash
import math, random, datetime

def level_required(level):
	def level_required_wrap(func):    
		@wraps(func)
		def d_view(*args, **kwargs):
			try:
				if current_user.level >= level:
					return func(*args, **kwargs)
			except Exception as e:
				print("Exception occured", e)
				flash('You are Unauthorized to access it')
				return redirect(url_for('home'))
			flash('You are Unauthorized to access it')
			return redirect(url_for('home'))
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

@app.route("/", methods=['GET','POST'])
@login_required
def home():
	if current_user.level >= 1:
		return render_template('admin.html', user=current_user, title='Admin Dashboard')
	elif current_user.level == 0:
		return render_template('user.html', user=current_user, title='User Dashboard')
	elif current_user.level == -1:
		form = VerifyEmail()
		form.id.data = current_user.id
		if form.validate_on_submit():
			current_user.level=0
			db.session.commit()
			return redirect(url_for('home'))
		return render_template('verify_email.html', user=current_user, form=form, title='Verify Email')
	
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
    	user = User(roll=form.roll.data.lower(), email=form.email.data.lower(), fname=form.fname.data, lname=form.lname.data, verify=generateOTP())
    	user.set_password(form.password.data)
    	db.session.add(user)
    	db.session.commit()
    	try:
    		email_new_user(user)
    	except Exception as e:
    		print(e)
    	flash('Congratulations, you are now a registered user!')
    	return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
def logout():
 	logout_user()
 	return redirect(url_for('home'))

@app.route('/resend')
@login_required
def resend():
	if current_user.level>=0:
		return redirect(url_for('home'))
	else:
		try:
			email_new_user(current_user)
		except Exception as e:
			print(e)
		flash("Mail Sent, Check your inbox")
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
		try:
			email_new(user,courier)
		except Exception as e:
			print (e)
		flash('Successfully Added')
		return redirect(url_for('home'))
	return render_template('add.html', title='Add', form=form)

@app.route('/admin/uncollected')
@login_required
@level_required(1)
def uncollected_admin():
	couriers = db.session.query(Courier,User).filter(Courier.recv==User.id, Courier.collected== False, Courier.returned== False).all()
	return render_template('uncollected_admin.html', title='Uncollected', couriers=couriers)

@app.route('/admin/collected')
@login_required
@level_required(1)
def collected_admin():
	couriers = db.session.query(Courier,User).filter(Courier.recv==User.id, Courier.collected== True, Courier.returned== False).order_by(Courier.collected_time.desc()).all()
	return render_template('collected_admin.html', title='Collected', couriers=couriers)

@app.route('/admin/mark', methods=['GET', 'POST'])
@login_required
@level_required(1)
def mark_collected():
	try:
		courier_id = int(request.args.get("id"))
	except Exception as e:
		print (e)
		flash('Invalid Courier Id')
		return redirect(url_for('home'))
	courier = Courier.query.filter_by(id=courier_id, collected=False).first()
	if not courier:
		flash('Invalid Courier Id')
		return redirect(url_for('home'))
	user = User.query.filter_by(id=courier.recv).first()
	form = MarkCollected()
	form.id.data = courier_id
	if form.validate_on_submit():
		courier.collected=True
		courier.collected_time= datetime.datetime.now()
		db.session.commit()
		try:
			email_collected(user,courier)
		except Exception as e:
			print (e)
		flash('Courier Marked as Collected')
		return redirect(url_for('home'))
	return render_template('mark_collected.html',title='Mark',form=form, courier=courier, user=user)

@app.route('/user/uncollected')
@login_required
@level_required(0)
def uncollected_user():
	couriers = db.session.query(Courier,User).filter(Courier.recv==User.id, Courier.collected== False, User.id==current_user.id, Courier.returned== False).all()
	return render_template('uncollected_user.html', title='Uncollected', couriers=couriers)

@app.route('/user/collected')
@login_required
@level_required(0)
def collected_user():
	couriers = db.session.query(Courier,User).filter(Courier.recv==User.id, Courier.collected== True, User.id==current_user.id, Courier.returned== False).all()
	return render_template('collected_user.html', title='Uncollected', couriers=couriers)

@app.route('/user/resend', methods=['GET', 'POST'])
@login_required
@level_required(0)
def resend_key():
	try:
		courier_id = int(request.args.get("id"))
	except Exception as e:
		print (e)
		flash('Invalid Courier Id')
		return redirect(url_for('home'))
	courier = Courier.query.filter_by(id=courier_id, collected=False).first()
	if not courier:
		flash('Invalid Courier Id')
		return redirect(url_for('home'))
	user = User.query.filter_by(id=courier.recv).first()
	if user.id != current_user.id:
		flash('Invalid Courier Id')
		return redirect(url_for('home'))
	try:
		email_new(user,courier)
	except Exception as e:
		print (e)
	flash('Check email inbox for verification key')
	return redirect(url_for('uncollected_user'))

@app.route('/user/cod', methods=['GET', 'POST'])
@login_required
@level_required(0)
def addcod():
	form = AddCodForm()
	if form.validate_on_submit():
		user = current_user
		codcourier = CourierCod(title=form.title.data, recv=user.id , tracking_id=form.tracking_id.data, amount=form.amount.data)
		db.session.add(codcourier)
		db.session.commit()
		try:
			email_new_cod(user,codcourier)
		except Exception as e:
			print (e)
		flash('Successfully Requested Cod')
		return redirect(url_for('home'))
	return render_template('codadd.html', title='COD Request', form=form)

@app.route('/user/codlist')
@login_required
@level_required(0)
def codlist():
	couriers = db.session.query(CourierCod,User).filter(CourierCod.recv==User.id, User.id==current_user.id).order_by(CourierCod.id.desc()).all()
	return render_template('codlist.html', title='COD List', couriers=couriers)

@app.route('/admin/pendingcod')
@login_required
@level_required(1)
def pendingcod():
	couriers = db.session.query(CourierCod,User).filter(CourierCod.recv==User.id, (CourierCod.approved==False or CourierCod.arrived== False) ).order_by(CourierCod.id.desc()).all()
	return render_template('admincp.html', title='COD Pending List', couriers=couriers)

@app.route('/admin/approve', methods=['GET', 'POST'])
@login_required
@level_required(1)
def approve():
	try:
		courier_id = int(request.args.get("id"))
	except Exception as e:
		print (e)
		flash('Invalid COD Id')
		return redirect(url_for('home'))
	courier = CourierCod.query.filter_by(id=courier_id, approved=False).first()
	if not courier:
		flash('Invalid COD Id')
		return redirect(url_for('home'))
	user = User.query.filter_by(id=courier.recv).first()
	courier.approved=True
	db.session.commit()
	try:
		email_cod_approved(user,courier)
	except Exception as e:
		print (e)
	flash('Successfully Approved')
	return redirect(url_for('home'))

@app.route('/admin/arrived', methods=['GET', 'POST'])
@login_required
@level_required(1)
def arrived():
	try:
		courier_id = int(request.args.get("id"))
	except Exception as e:
		print (e)
		flash('Invalid COD Id')
		return redirect(url_for('home'))
	courier = CourierCod.query.filter_by(id=courier_id, arrived=False, approved=True).first()
	if not courier:
		flash('Invalid COD Id')
		return redirect(url_for('home'))
	user = User.query.filter_by(id=courier.recv).first()
	courier.arrived=True
	key  = generateOTP()
	c = Courier(title=courier.title, recv=user.id, verify_key=key, tracking_id=courier.tracking_id)
	db.session.add(c)
	db.session.commit()
	try:
		email_new(user,courier)
	except Exception as e:
		print (e)
	flash('Successfully Marked as Arrived')
	return redirect(url_for('home'))

@app.route('/admin/completedcod')
@login_required
@level_required(1)
def completedcod():
	couriers = db.session.query(CourierCod,User).filter(CourierCod.recv==User.id, CourierCod.approved==True, CourierCod.arrived== True).order_by(CourierCod.id.desc()).all()
	return render_template('adminca.html', title='COD Pending List', couriers=couriers)