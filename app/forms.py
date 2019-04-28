from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from app.models import User, Courier, CourierCod

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired()], render_kw={"placeholder": "First Name"})
    lname = StringField('Last Name', validators=[DataRequired()], render_kw={"placeholder": "Last Name"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "Email"})
    roll = StringField('Roll Number', validators=[DataRequired()], render_kw={"placeholder": "Roll Number"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"placeholder": "Password"})
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "Repeat Password"})
    submit = SubmitField('Register')

    def validate_roll(self, roll):
        user = User.query.filter_by(roll=roll.data).first()
        if user is not None:
            raise ValidationError('Roll number already registered')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Email already registered')

    def validate_password(self,password):
    	if len(password.data) < 8 and len(password.data) >16:
    		raise ValidationError('Please keep a password with length between 8 and 16 characters')

class AddForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()], render_kw={"placeholder": "Title"})
	roll = StringField('Recipient roll number', validators=[DataRequired()], render_kw={"placeholder": "Recepient roll number"})
	tracking_id = StringField('Tracking Id',validators=[DataRequired()], render_kw={"placeholder": "Tracking ID"})
	submit = SubmitField('Add')
	def validate_roll(self,roll):
		user = User.query.filter_by(roll=roll.data.lower()).first()
		if user is None:
			raise ValidationError('Please use a valid roll number.')

class MarkCollected(FlaskForm):
	id = IntegerField('Courier Id', validators=[DataRequired()], render_kw={"placeholder": "Courier ID"})
	key = StringField('Verification Key', validators=[DataRequired()], render_kw={"placeholder": "Verification Key"})
	submit = SubmitField('Mark as Collected')
	def validate_key(self, key):
		courier = Courier.query.filter_by(id=self.id.data).first()
		if courier is None or courier.verify_key != key.data or courier.collected == True:
			raise ValidationError('Invalid Key or Courier')

class VerifyEmail(FlaskForm):
	id = IntegerField('User Id', validators=[DataRequired()], render_kw={"placeholder": "User ID"})
	key = StringField('Verification Key', validators=[DataRequired()], render_kw={"placeholder": "Verification Key"})
	submit = SubmitField('Verify Email')
	def validate_key(self,key):
		user = User.query.filter_by(id=self.id.data).first()
		if user is None or user.verify != key.data :
			raise ValidationError('Invalid key')


class AddCodForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()], render_kw={"placeholder": "Title"})
	tracking_id = StringField('Tracking Id',validators=[DataRequired()], render_kw={"placeholder": "Tracking ID"})
	amount = IntegerField('Amount', validators=[DataRequired()], render_kw={"placeholder": "Amount"})
	submit = SubmitField('Request')
	def validate_roll(self,roll):
		user = User.query.filter_by(roll=roll.data.lower()).first()
		if user is None:
			raise ValidationError('Please use a valid roll number.')
