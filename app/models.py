from app import db
from app import login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
	id = db.Column(db.Integer(), primary_key=True, autoincrement= True)
	email = db.Column(db.String(256),index=True)
	fname = db.Column(db.String(75), nullable=False)
	lname = db.Column(db.String(75))
	roll = db.Column(db.String(100), unique=True, index=True)
	password_hash = db.Column(db.String(256))
	verify = db.Column(db.String(256),unique=True)
	level = db.Column(db.Integer, default=0)

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

@login.user_loader
def load_user(id):
	return User.query.get(id)