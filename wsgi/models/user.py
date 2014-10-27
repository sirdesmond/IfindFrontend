#!/usr/bin/env python

from ifindapp import db
from flask import current_app
from flask.ext.login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import pdb
import json
from schema import (Schema, Optional, And, Use)
from validate_email import validate_email
from firebase_token_generator import create_token

# mongodb://<dbuser>:<dbpassword>@ds053459.mongolab.com:53459/ifindcard
user_full_with_hash = Schema({
    'email': validate_email,
    'f_name': basestring,
    'l_name': basestring,
    'password': basestring,
    'role': basestring,
    'p_number': basestring,
    'country': basestring
})

user_full = Schema({        
    'email': validate_email,
    'u_name': basestring,
    'f_name': basestring,
    'l_name': basestring,
    'role': basestring,
    'country':basestring,
    '_type': int
})

user_profile_partial = Schema({
    'id': basestring,
})

class Status(db.EmbeddedDocument):
    verified = db.BooleanField()
    vcode = db.StringField()
    vcode_exp = db.FloatField()

class Profile(db.EmbeddedDocument):
    bsid = db.StringField()
    bsname = db.StringField()



class User(db.DynamicDocument, UserMixin):
    email = db.StringField(required=True, unique=True)
    f_name = db.StringField(required=True, max_length=64)
    l_name = db.StringField(required=True, max_length=64)
    role = db.StringField(required=True, max_length=64)
    password_hash = db.StringField(required=True, max_length=128)
    username = db.StringField(required=True, max_length=64)
    country = db.StringField(required=True, max_length=64)
    v_status = db.EmbeddedDocumentField(Status)
    profile = db.EmbeddedDocumentField(Profile)
    bun = db.StringField(unique=True, max_length=28)
    p_number = db.StringField(unique=True, max_length=10)


    def json_to_doc(self, json_data=None):

        if json_data:
            try:
                self.email = json_data.get('email')
                self.role = json_data.get('role')
                self.password = json_data.get('password')
                self.f_name = json_data.get('f_name')
                self.l_name = json_data.get('l_name')
                self.p_number = json_data.get('p_number')
                self.country = json_data.get('country')

            except Exception, e:
                raise e

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        print self.id
        return s.dumps({'id': str(self.id)})

    def generate_fb_token(self, payload=None, expiration=None):

        return create_token("FgUjXoxvFKgsUDdgfONGnOqP3dOi9ZZe3Kkb5bXK",
                            payload)

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        print User.objects.get(id=data['id'])
        return User.objects.get(id=data['id'])

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self._id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        pdb.set_trace()
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self._id:
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
        return s.dumps({'reset': self._id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self._id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.email, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self._id:
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

    def to_json(self, _type=0, with_hash=False):
        uid = str(self.id)
        print type(uid)
        json_user = {}
        if _type == 0:
            json_user = {
                'userid': uid,
                'email': self.email,
                'f_name': self.f_name,
                'l_name': self.l_name,
                'role': self.role,
                'country': self.country,
            }
        if _type == 1:
            json_user = {
                'userid': uid,
                'email': self.email,
                'f_name': self.f_name,
                'l_name': self.l_name,
                'role': self.role,
                'country': self.country,
                'bun': self.bun,
                'p_number':self.p_number,
                'profile': {
                    'bsid': self.profile.bsid,
                    'bsname': self.profile.bsname
                }

            }


        if with_hash:
            # When generating the new user these field need to be availabe
            json_user['password_hash'] = self.password_hash
            json_user['p_number'] = self.p_number
            del json_user['userid']
        try:
            json_user['verified'] = self.v_status.verified
        except Exception, e:
            print str(e)       

        return json.dumps(json_user)

# =============================== Business Object ============================

