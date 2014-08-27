from flask import (Blueprint, request, g, jsonify)
from models import User
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_error)
from flask.ext.cors import cross_origin
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
        user = User.objects.get(email=uname)

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

        fb_payload = {"id": g.current_user.userid}

        response = {
            'ifcToken': g.current_user.generate_auth_token(
                expiration=3600),
            'ifcexp': 3600,
            'fbToken': g.current_user.generate_fb_token(payload=fb_payload)
        }
        print type(g.current_user)
        return make_ok(tokens=response, user=g.current_user.to_json())

    # @cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
    def options(self):
        print 'I GOT CALLED'
        pass
