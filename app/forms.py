from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from app.models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    roll = StringField('Roll Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_roll(self, roll):
        user = User.query.filter_by(roll=roll.data).first()
        if user is not None:
            raise ValidationError('Please use a different Roll Number.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

    def validate_password(self,password):
    	if len(password.data) < 8:
    		raise ValidationError('Please keep a password longer than 8 characters')

class AddForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()])
	roll = StringField('Recipient Roll Number', validators=[DataRequired()])
	submit = SubmitField('Add')
	def validate_roll(self,roll):
		user = User.query.filter_by(roll=roll.data.lower()).first()
		if user is None:
			raise ValidationError('Please use a valid Roll Number.')
