from flask import (Blueprint, request, g, jsonify)
from models import User
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_error)
from flask.ext.cors import cross_origin
blueprint = Blueprint(__name__, __name__)


@blueprint.route('', methods=['GET', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class Business(CORSObject):

    def verify_token(*args, **kwargs):
        try:
            token = str(request.headers).split(
                'Authorization: Basic ')[1].split('\r')[0]
            print 'From verify token' + token
            user = User.verify_auth_token(token)

            if not user:
                added_headers = None
                return make_error('Invalid token', 401,
                                  additional_headers=added_headers)

            g.current_user = user
            return None

        except Exception, e:
            return make_error(str(e), 401)

    @validate_credentials(verify_token)
    def get(self, typ=0, params='*' ):
        """ Used for seaching for Business dynamically.
        When the type is dynamically we will use specially field in the
        collection to find the Business that best matches the query.
        """

        
        return make_ok(data={'params':request.args.get("params"), 'type': request.args.get("typ")})
