import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'default secret'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587  # SSL - 465
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    IFIND_MAIL_SUBJECT_PREFIX = '[IFindCard]'
    IFIND_MAIL_SUBJECT_CONFIRM = ' Confirm Your Account'
    IFIND_MAIL_TEMP_CONFRIM = '/auth/email/confirm'
    IFIND_MAIL_SENDER = 'IFindCard Admin <ifind@example.com>'
    IFIND_ADMIN = os.environ.get('IFIND_ADMIN')

    @staticmethod
    def init_app(app):
        pass


class DevConfig(Config):
    DEBUG = True

    # replace with environment variables
    MONGODB_SETTINGS = {
        "DB": "ifindcard",
        "USERNAME": "desmond",
        "PASSWORD": "desmond",
        "HOST": "ds053459.mongolab.com",
        "PORT": 53459
    }

    # SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL')or\
    #'sqlite:///' + os.path.join(basedir,'data-dev.sqlite'

config = {
    'development': DevConfig,
    'default': DevConfig
}
