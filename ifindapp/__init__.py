from flask import Flask
from flask.ext.mongoalchemy import MongoAlchemy
from flask.ext.mail import Mail
from config import config
from flask.ext.login import LoginManager
from flask.ext.mongoengine import MongoEngine
from pymongo import MongoClient

db = MongoEngine()
mail = Mail()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
#login_manager.login_view = ''

def create_app(config_name):
	app = Flask(__name__)
	app.config.from_object(config[config_name])
	mail.init_app(app)
	db.init_app(app)
	login_manager.init_app(app)

	from .api_1_0 import api as api_blueprint
	app.register_blueprint(api_blueprint,url_prefix='/api/v1.0')

	return app
