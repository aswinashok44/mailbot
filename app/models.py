from app import db

class User(db.Model):
	email = db.Column(db.String(256),primary_key=True)
	fname = db.Column(db.String(75), nullable=False)
	lname = db.Column(db.String(75))
	roll = db.Column(db.String(100), unique=True, index=True)
	password_hash = db.Column(db.String(128))
	verify = db.Column(db.String(256),unique=True)