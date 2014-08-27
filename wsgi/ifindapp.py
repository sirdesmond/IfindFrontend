#!/usr/bin/python
from flask import Flask
from flask.ext.mongoengine import MongoEngine
from config import config
from lib import use_pretty_default_error_handlers


app = Flask(__name__)
app.config.from_object(config['default'])
use_pretty_default_error_handlers(app)

db = MongoEngine(app)
import views
views
print 'DONE WITH FLASK APP DEPENDCIES'
