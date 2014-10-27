
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
from requests import put, get, post
from bson.objectid import ObjectId
import time, os, json, base64, hmac, urllib
from hashlib import sha1
import datetime
import boto
from boto.s3.connection import OrdinaryCallingFormat
from boto.s3 import connect_to_region
from boto.s3.connection import Location

auth = HTTPBasicAuth()




@auth.verify_password
def verify_password(email_or_token, password):
	
	print 'email_or_token :'+ email_or_token
	print 'username:'+request.authorization.username
	try:
		token = str(request.headers).split('Authorization: Basic ')[1].split('\r')[0]
		print 'Real token '+ token
		user = User.verify_auth_token(token)
		if user is not None:
			g.current_user = user 
			g.token_used = True
			return g.current_user is not None

	except Exception, e:
		print e
		pass

	if email_or_token == '':
		g.current_user = AnonymousUser()
		return True

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

#@auth.login_required
def search(searchterm, category):
	response = {}
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


@api.route('/signs3/<bunid>',methods=['GET','OPTIONS'])
@cross_origin(origins='*',headers=[])
def sign_s3(bunid):
	response={}
	access_key = os.environ['AWS_ACCESS_KEY_ID']
	secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
	bucket = 'ifindcard'
	signed_urls = []
	count = 0
	conn = boto.connect_s3(aws_access_key_id = access_key,aws_secret_access_key = secret_key)

	for bucket in conn.get_all_buckets():
		print "{name}\t{created}".format(name = bucket.name,created = bucket.creation_date)

	for key in conn.get_bucket('ifindcard'):
		if str(bunid) in str(key):
			key.set_canned_acl('private')
			print "{name}\t{size}\t{modified}".format(name=key.name,size=key.size,modified=key.last_modified)
			url = key.generate_url(60, method='GET',query_auth=True, force_http=True)

			signed_urls.append(url)
		else:
			pass

	for url in signed_urls:
		count = count +1;
		response[count] = url
	return jsonify(response=response)


# @api.route('/signs3',methods=['GET','OPTIONS'])
# @cross_origin(origins='*',headers=[])
# def sign_s3():
# 	response={}
# 	AWS_ACCESS_KEY = 'AKIAJ6TLOGEVEZX77OUA'
# 	AWS_SECRET_KEY = '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'
# 	S3_BUCKET = 'ifindcard'
# 	signed_urls = []
# 	count = 0

# 	conn = boto.connect_s3(aws_access_key_id = AWS_ACCESS_KEY,aws_secret_access_key = AWS_SECRET_KEY)

# 	expires = long(time.time()+ 20)
# 	expiration= datetime.datetime.utcfromtimestamp(expires).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
# 	t = datetime.datetime.utcnow()
# 	amzdate = t.strftime('%Y%m%dT%H%M%SZ')

# 	amz_headers = "x-amz-acl:private"

# 	for key in conn.get_bucket('ifindcard'):
# 		get_request = "GET\n\n\n%d\n%s\n/%s/%s" % (expires, amz_headers, S3_BUCKET, key.name)
# 		signature = base64.encodestring(hmac.new(AWS_SECRET_KEY, get_request, sha1).digest())
# 		signature = urllib.quote_plus(signature.strip())	
# 		url = 'https://%s.s3.amazonaws.com/%s?' % (S3_BUCKET,key.name)

# 		payload = {'AWSAccessKeyId':AWS_ACCESS_KEY,'Expires':expires,'Signature':signature}

# 		signed = url + urllib.urlencode(payload)

# 		print signed
# 		signed_urls.append(signed)

# 	for url in signed_urls:
# 		count = count +1;
# 		response[count] = url
# 	return jsonify(response=response)


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