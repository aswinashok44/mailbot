import os

class Config(object):
    POSTGRES = {
    'user': 'postgres',
    'pw': 'vidyut2019*',
    'db': 'mailbot',
    'host': 'localhost',
    'port': '5432',
    }
    SQLALCHEMY_DATABASE_URI = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'mailbot2019*'

