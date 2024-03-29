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
    smtpserver.sendmail(Config.MAIL_DEFAULT_SENDER, recipient, msg.as_string())
    smtpserver.close()

def email_new(user,courier):
    send_mail("You have a new Courier - Mailbot", 
            htmlbody=render_template('emails/new.html', user=user, courier=courier), 
            recipient=user.email
            )
    return "success"

def email_collected(user,courier):
    send_mail("Courier Collected - Mailbot", 
            htmlbody=render_template('emails/collected.html', user=user, courier=courier), 
            recipient=user.email
            )
    return "success"

def email_returned(user,courier):
    send_mail("Courier Returned - Mailbot", 
            htmlbody=render_template('emails/returned.html', user=user, courier=courier), 
            recipient=user.email
            )
    return "success"


def email_new_user(user):
    send_mail("Welcome - Mailbot", 
            htmlbody=render_template('emails/new_user.html', user=user), 
            recipient=user.email
            )
    return "success"

def email_new_cod(user,courier):
    send_mail("You Requested a COD Courier - Mailbot", 
            htmlbody=render_template('emails/codnew.html', user=user, courier=courier), 
            recipient=user.email
            )
    return "success"

def email_cod_approved(user,courier):
    send_mail("You COD Approved - Mailbot", 
            htmlbody=render_template('emails/codapproved.html', user=user, courier=courier), 
            recipient=user.email
            )
    return "success"