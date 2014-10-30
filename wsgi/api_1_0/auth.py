from flask import (Blueprint, request, g, jsonify)
from models.user import User
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_error)
from tasks.tasks import forgot_password
from flask.ext.cors import cross_origin
import boto
from boto.s3 import connect_to_region
import os

blueprint = Blueprint(__name__, __name__)


@blueprint.route('', methods=['POST', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class Auth(CORSObject):

    def verify_password(self, *args, **kwargs):
        print 'Request Header POST:AUTH \n' + str(request.headers)
        auth = request.authorization
        uname = auth.username
        c_password = auth.password
        user = {}
        try:
            user = User.objects.get(email=uname)  
        except Exception, e:
            print str(e)

        if not user:
            added_headers = None
            return make_error('Invalid username or password', 401,
                              additional_headers=added_headers)

        g.current_user = user
        added_headers = None
        return make_error('Invalid username or password', 401,
                          additional_headers=added_headers) if not user.verify_password(c_password) else None

    @validate_credentials(verify_password)
    def post(self):
        print 'Request Header POST:AUTH \n' + str(request.headers)
        print 'User id' + str(g.current_user.id)
        fb_payload = {"id": str(g.current_user.id)}

        response = {
            'ifcToken': g.current_user.generate_auth_token(
                expiration=3600),
            'ifcexp': 3600,
            'fbToken': g.current_user.generate_fb_token(payload=fb_payload)
        }
        return make_ok(tokens=response, user=g.current_user.to_json())




@blueprint.route('/forgotpassword', methods=['POST', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class UserManager(CORSObject):

     def post(self):
        response = {}
        data = request.json['data']

        input_json = {str(k): str(v) for k, v in data.iteritems()}
        try:
            user = User.objects.get(email=input_json['email'])  
        except Exception, e:
            print str(e)

        if not user:
            make_error('user not exist')

        print "This is the user being processed :" + user

        result = forgot_password.apply_async(user.email)
        response['message'] = 'temporary password sent'

        return make_ok()



@blueprint.route('/signs3/<bunid>',methods=['GET','OPTIONS'])
@cross_origin(origins='*',headers=['Authorization'])
def sign_s3(bunid):
    response=[]
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
            url = key.generate_url(3600, method='GET',query_auth=True, force_http=True)

            signed_urls.append(url)
        else:
            pass

    for url in signed_urls:
        response.append(url)
    return jsonify(response=response)