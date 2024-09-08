import os

class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/lab6'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'paudel.ankit99@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'gihx fbkq jznu llko')
