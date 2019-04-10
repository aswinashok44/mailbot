from app import app
from flask import render_template
from app import app
from app.forms import LoginForm
from flask import render_template, redirect
@app.route("/")
def hello():
	return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		print (form.username.data)
		return redirect('/')
	return render_template('login.html', form=form)
