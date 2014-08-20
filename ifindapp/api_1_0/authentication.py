from flask import g, jsonify,request
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.login import login_user, logout_user, login_required, \
	current_user
from ..models import User, AnonymousUser
from . import api
from .. import db
from ..email import send_email
from ..errors import unauthorized, forbidden
from ..decorators import crossdomain
from flask.ext.cors import cross_origin
import pdb
import traceback
from werkzeug.security import generate_password_hash,check_password_hash
from firebase_token_generator import create_token
import time
import os
import json
from requests import put,get,post


auth = HTTPBasicAuth()



#arbitrary_auth_payload = {"auth_data": "foo", "other_auth_data": "bar"}
#options = {"admin": True}
#token = create_token("<YOUR_FIREBASE_SECRET>", arbitrary_auth_payload, options)

@auth.verify_password
def verify_password(email_or_token, password):
	if email_or_token == '':
	    g.current_user = AnonymousUser()
	    return True
	if password == '':
	    g.current_user = User.verify_auth_token(email_or_token)
	    g.token_used = True
	    return g.current_user is not None
	user = User.objects.get(email=email_or_token)

	if not user:
	    return False
	g.current_user = user
	g.token_used = False
	return user.verify_password(password)


@auth.error_handler
def auth_error():
    return unauthorized('Invalid credentials')



@api.route('/login',methods=['GET','POST','OPTIONS'])
@cross_origin(origins='*',headers=['Authorization','Content-Type'])
@auth.login_required
def get_token():
	if g.current_user.is_anonymous() or g.token_used:
	    return jsonify(make_response(unauthorized('Invalid credentials')))
	return jsonify({'token': g.current_user.generate_auth_token(
	    expiration=3600), 'expiration': 3600,'username':g.current_user.username})




@api.route('/register', methods=['POST','OPTIONS'])
@cross_origin(origins='*',headers=['Content-Type'])
def register():
	response = {}
###make POST request###
	data = request.json	
	if 'password' in data:
		password = data['password']
	if 'username' in data:
		username = data['username']
	if 'email' in data:
		email = data['email']



	try:

		### generate BUN ID here and add to json object
		## make post request
		r= post('http://wrkapi-naytion.rhcloud.com/v1/user/user002',data=json.dumps(data),headers={'Content-Type':'application/json'})
		response["status"] = r.status_code
		response["message"] = r.text

	except Exception, e:
		response["status"] = 400
		response["message"] = e.message
		

	return jsonify(response=response)
##verification via email or phone



@api.route('/search/:searchterm',methods=['GET'])
@cross_origin(origins='*')
def search():
	response={}

	##retrieve contents from request
	data = request.json
	
	##validate content - 
	

	##query database for content
	
	##return to user

@api.route('/activate', methods=['POST','OPTIONS'])
@cross_origin(origins='*',headers=['Authorization','Content-Type'])
@auth.login_required
def activate():
	if g.current_user.confirmed:
		#already confirmed
		return jsonify({'message':'already confirmed'})
	if g.current_user.confirm():
		status = 200
	   # flash('You have confirmed your account. Thanks!')		
	else:
		status = 400
		#flash('The confirmation link is invalid or has expired.')
	return jsonify({"status":status})



@api.route('/unconfirmed')
@cross_origin(origins='*',headers=['Authorization','Content-Type'])
def unconfirmed():
	response = {}
	if g.current_user.is_anonymous() or g.current_user.confirmed:
		response['redirect'] = 'index'
	response['message'] = 'unconfirmed'
	return jsonify(response=response)


@api.route('/change-password', methods=['GET', 'POST'])
@cross_origin(origins='*',headers=['Authorization','Content-Type'])
@auth.login_required
def change_password():
	response = {}
	if request.method=='POST':
		###make PUT request here###
		if current_user.verify_password(form.old_password.data):
			current_user.password = form.password.data
			db.session.add(current_user)
			response['message']='Your password has been updated.'
			response['redirect'] = 'index'
			return jsonify(response=response)
		else:
			pass



@api.route('/reset/<token>', methods=['GET', 'POST'])
@cross_origin(origins='*',headers=['Authorization','Content-Type'])
def password_reset(token):

	response = {}
	if not current_user.is_anonymous():
		return jsonify({'message':'redirect to login'})
	if request.method=='POST':
		###make request here with token###
		user = User.query.filter_by(email=form.email.data).first()
		if user is None:
			return jsonify({'message':'redirect to login'})
		if user.reset_password(token, form.password.data):
			#password updated
			response['message']='redirect to login'
		else:
			response['message']='redirect to index'
		return jsonify(response=response)



@api.route('/change-email/<token>')
@cross_origin(origins='*',headers=['Authorization','Content-Type'])
@auth.login_required
def change_email(token):

	###make PUT request with token###
	response = {}
	if g.current_user.change_email(token):
		#flash('Your email address has been updated.')
		response['message']='email address updated'
	else:
		response['message']='invalid request'
	return jsonify(response=response)