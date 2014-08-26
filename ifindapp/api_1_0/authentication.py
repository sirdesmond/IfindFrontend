from flask import g, jsonify, request, session, Response
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.login import login_user, logout_user, login_required, \
	current_user
from ..models import User, AnonymousUser
from . import api
from .. import db
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
from requests import put, get, post
from bson.objectid import ObjectId


auth = HTTPBasicAuth()




@auth.verify_password
def verify_password(email_or_token, password):
	print str(request.headers).split('Authorization: Basic ')[1].split('\r')[0]
	print 'email_or_token :'+ email_or_token+password
	print 'password:'+password
	# print request.headers['Token']
	if email_or_token == '':
	    g.current_user = AnonymousUser()
	    return True
	if password == '':
		g.current_user = User.verify_auth_token(email_or_token)
		g.token_used = True
		return g.current_user is not None

	user = User.objects.get(email=email_or_token)
	print user

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
	print 'This is the request header right now\n' + str(request.headers)

	if g.current_user.is_anonymous() or g.token_used:
	    return jsonify(make_response(unauthorized('Invalid credentials')))

	##return token.fb token and user object
	payload = {"id": g.current_user.userid}
	token = create_token("FgUjXoxvFKgsUDdgfONGnOqP3dOi9ZZe3Kkb5bXK",payload)
	

	
	return jsonify({'token': unicode(g.current_user.generate_auth_token(
	    expiration=3600)), 'expiration': 3600, 'user':g.current_user.to_json(),'fbToken':token})




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

		### generate new Ifind ID here and add to json object
		
		## make post request
		r= post('http://wrkapi-naytion.rhcloud.com/v1/user/user002',data=json.dumps(data),headers={'Content-Type':'application/json'})
		response["status"] = r.status_code
		response["message"] = r.text

	except Exception, e:
		response["status"] = 400
		response["message"] = e.message
		

	return jsonify(response=response)
##verification via email or phone



@api.route('/search/<searchterm>/<category>',methods=['GET', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization'])
@auth.login_required
def search(searchterm, category):
	
	print 'This is the request header right now from seach: \n' + str(request.headers)

	##analyze searchterm
	##if searchcategory is 0=BUN#,1=PHONE#,2=QRCODE
	if category == '0':
		user = User.objects.get(userid=searchterm)
	elif category == '1':
		user = User.objects.get(phone=searchterm)
	elif category == '2':
		user = User.objects.get(email=searchterm)

	
	response['user'] = user.to_json()

			
	return jsonify(response=response)

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