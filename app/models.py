from app import db
from app import login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True, autoincrement= True)
	email = db.Column(db.String(256),index=True)
	fname = db.Column(db.String(75), nullable=False)
	lname = db.Column(db.String(75))
	roll = db.Column(db.String(100), unique=True, index=True)
	password_hash = db.Column(db.String(256))
	verify = db.Column(db.String(256))
	level = db.Column(db.Integer, default=-1)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

	def super(self):
		return self.email=='aswin.ashok44@gmail.com'

@login.user_loader
def load_user(id):
	return User.query.get(id)

class Courier(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	recv = db.Column(db.Integer, db.ForeignKey(User.id))
	title = db.Column(db.String(256))
	tracking_id = db.Column(db.String(256))
	recv_time = db.Column(db.DateTime, default=datetime.datetime.now)
	collected = db.Column(db.Boolean, default=False)
	returned = db.Column(db.Boolean, default=False)
	collected_time = db.Column(db.DateTime)
	verify_key = db.Column(db.String(6))

class CourierCod(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	recv = db.Column(db.Integer, db.ForeignKey(User.id))
	title = db.Column(db.String(256))
	tracking_id = db.Column(db.String(256))
	amount = db.Column(db.Integer)
	approved = db.Column(db.Boolean, default=False)
	arrived = db.Column(db.Boolean, default=False)
