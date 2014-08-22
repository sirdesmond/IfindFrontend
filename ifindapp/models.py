#!/usr/bin/env python

from ifindapp import db,login_manager
from flask import current_app
from flask.ext.login import UserMixin,AnonymousUserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import pdb 

## mongodb://<dbuser>:<dbpassword>@ds053459.mongolab.com:53459/ifindcard

class User(db.Document,UserMixin):
	_id=db.IntField(required=True,primary_key=True,unique=True)
	email = db.StringField(required=True)
	username = db.StringField(required=True,max_length=64)
	role = db.StringField(required=True,max_length=64)
	_type =db.IntField(required=True)
	password_hash = db.StringField(required=True,max_length=128)
	confirmed = db.BooleanField(default=False)

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')
	
	@password.setter
	def password(self,password):
		self.password_hash = generate_password_hash(password)
	
	def verify_password(self,password):
		return check_password_hash(self.password_hash,password)
	
	def generate_auth_token(self,expiration):
		s = Serializer(current_app.config['SECRET_KEY'],\
			expires_in=expiration)
		return s.dumps({'id':self.id})

	@staticmethod
	def verify_auth_token(token):
		s= Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return None
		return User.objects.get(id=data['id'])

	def generate_confirmation_token(self, expiration=3600):
	    s = Serializer(current_app.config['SECRET_KEY'], expiration)
	    return s.dumps({'confirm': self.id})

	def confirm(self, token):
	    s = Serializer(current_app.config['SECRET_KEY'])
	    pdb.set_trace()
	    try:
	        data = s.loads(token)
	    except:
	        return False
	    if data.get('confirm') != self.id:
	        return False
	    self.confirmed = True
	    db.session.add(self)
	    return True

	def confirm(self):
		self.confirmed = True
		db.session.add(self)
		return True

	def generate_reset_token(self, expiration=3600):
	    s = Serializer(current_app.config['SECRET_KEY'], expiration)
	    return s.dumps({'reset': self.id})

	def reset_password(self, token, new_password):
	    s = Serializer(current_app.config['SECRET_KEY'])
	    try:
	        data = s.loads(token)
	    except:
	        return False
	    if data.get('reset') != self.id:
	        return False
	    self.password = new_password
	    db.session.add(self)
	    return True

	def generate_email_change_token(self, new_email, expiration=3600):
	    s = Serializer(current_app.config['SECRET_KEY'], expiration)
	    return s.dumps({'change_email': self.id, 'new_email': new_email})

	def change_email(self, token):
	    s = Serializer(current_app.config['SECRET_KEY'])
	    try:
	        data = s.loads(token)
	    except:
	        return False
	    if data.get('change_email') != self.id:
	        return False
	    new_email = data.get('new_email')
	    if new_email is None:
	        return False
	    if self.query.filter_by(email=new_email).first() is not None:
	        return False
	    self.email = new_email
	    self.avatar_hash = hashlib.md5(
	        self.email.encode('utf-8')).hexdigest()
	    db.session.add(self)
	    return True

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))
