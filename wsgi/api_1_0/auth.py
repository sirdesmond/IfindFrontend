from flask import (Blueprint, request, g, jsonify)
from models.user import (User, user_email)
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_error, validate_json)
from flask.ext.cors import cross_origin
from tasks.tasks import (reset_password,recover_password)
blueprint = Blueprint(__name__, __name__)


@blueprint.route('/<type>', methods=['POST', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class AuthBranch(CORSObject):

    @validate_json(user_email.validate)
    def post(self, type):
        print 'Type: ' + str(type)
        if type == "0001":
            print "We have a password recovery request "
            user = User.objects.get(email=g.data["email"])
            if not user:
                make_error("No User Exist", 201)

            result = recover_password.apply_async((g.data["email"],))
            return make_ok()
        elif type == "0002":
            #Verify Code REMEBER!!!!!!

            user = User.objects.get(email=g.data["email"])
            print "We have a password change form request "
            if user.v_status.pswrd_reset_code == g.data["code"]:
                response = {
                'ifcToken': user.generate_reset_token(
                    expiration=60*60),
                'ifcexp': 60*60,
                }
                print str(response)
                return make_ok(tokens=response, user=user.to_json())

        return make_error("Bad Request", 404)


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
