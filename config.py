import os

class Config(object):
    POSTGRES = {
    'user': 'vidyut',
    'pw': 'vidyut2018*',
    'db': 'vidyut',
    'host': 'ambvidyut-dev.ckhmnttmq7jx.ap-south-1.rds.amazonaws.com',
    'port': '5432',
    }
    SQLALCHEMY_DATABASE_URI = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'mailbot2019*'
    MAIL_SERVER = 'smtp.office365.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'aswin@am.students.amrita.edu'
    MAIL_PASSWORD = 'Hangover123'
    MAIL_DEFAULT_SENDER = 'aswin@am.students.amrita.edu'

