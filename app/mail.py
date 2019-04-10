import smtplib
from config import Config
from threading import Thread
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
from flask import render_template
from app.models import User, Courier

def send_mail(sub, htmlbody, recipient):
    smtpserver = smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT)
    smtpserver.ehlo()
    smtpserver.starttls()
    smtpserver.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
    msg = MIMEMultipart('alternative')
    msg['Subject'] = sub
    msg['From'] = Config.MAIL_DEFAULT_SENDER
    msg['To'] = recipient
    part1 = MIMEText(htmlbody, 'html')
    msg.attach(part1)
    smtpserver.sendmail(user, recipient, msg.as_string())
    smtpserver.close()

def email_new(user,courier):
    print(user, courier)
    send_mail("You have a new Courier", 
            htmlbody=render_template('emails/new.html', user=user, courier=courier), 
            recipient=user.email
            )
    return "success"