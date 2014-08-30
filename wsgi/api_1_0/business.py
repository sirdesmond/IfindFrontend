from flask import (Blueprint, request, g, jsonify)
from models import User
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_error)
from flask.ext.cors import cross_origin
blueprint = Blueprint(__name__, __name__)


@blueprint.route('', methods=['GET', 'POST' 'OPTIONS'])
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
    def get(self):
        """ Used for seaching for Business dynamically.
        When the type is dynamically we will use specially field in the
        collection to find the Business that best matches the query.
        Return info could include:
            Business info
            All Representives linked to Business
            One particular Representive
        Business Search TYPES:
            0 - BUN
            1 - PHONE
            2 - QRCODE
            3 - BUS NAME
            4 - DYNAMIC

        """
        q, typ = request.args.get("q"), request.args.get("typ")
        response = {}
        ##analyze searchterm
        ##if searchcategory is 0=BUN#,1=PHONE#,2=QRCODE
        if typ == '0':
            user = User.objects.get(userid=q)
        elif typ == '1':
            user = User.objects.get(phone=q)
        elif typ == '2':
            user = User.objects.get(email=q)

        response['user'] = user.to_json()

        return make_ok(data=response)

    # @validate_json(user_full_with_hash.validate)
    # def post(self):
    #     response = {}
    #     data = request.json['data']

    #     input_json = {str(k): str(v) for k, v in data.iteritems()}
    #     Business = Business()
    #     business.json_to_doc(json_data=input_json)
    #     input_json = business.to_json(with_hash=True)
    #     print str(input_json)

    #     new_business = str(input_json)
    #     result = chain(register_users.s(new_user), send_confirm_email.s()).apply_async()
    #     response['message'] = 'Registration submitted successfully'

    #     return make_ok(reponse=response)
