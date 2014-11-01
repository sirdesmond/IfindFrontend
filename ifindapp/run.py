
import sys
import os
from ifindapp import create_app,db
from flask import redirect
from models import User
from flask.ext.script import Manager,Shell, Server


app = create_app(os.environ.get('FLASK_CONFIG') or 'default')
manager = Manager(app)


def make_shell_context():
	return dict(app=app, db=db, User=User)

manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command("runserver", Server(use_debugger=True, use_reloader=True, host='0.0.0.0'))


@manager.command
def tests():
	import unittest as u
	'''Run my unit tests'''
	tests = u.TestLoader().discover('tests')
	u.TextTestRunner(verbosity=2).run(tests)

if __name__ == '__main__':
	manager.run() 
