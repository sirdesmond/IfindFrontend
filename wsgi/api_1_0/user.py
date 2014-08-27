from flask import Blueprint, request
from celery import chain
from models import (User, user_full, user_partial, user_full_with_hash)
from tasks.tasks import (register_users, send_confirm_email)
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_error, validate_json)

blueprint = Blueprint(__name__, __name__)


@blueprint.route('', methods=['POST', 'DELETE', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class Users(CORSObject):

    @validate_json(user_full.validate)
    def post(self):
        reponse = {}
        data = request.json
        user = User(json_data=data).to_json(with_hash=False)
        new_user = str(json.loads(user))
        print 'NEW USER: 'new_user

        chain(register_users.s(new_user), send_confirm_email.s()).apply_async()
        response['message'] = 'Registration submitted successfully'

        return make_ok(reponse=response)

    def delete(self):
        if False:
            user_database.reset()
            return make_ok(reponse=reponse)


@blueprint.route('/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
# @check(url_id_matches_body)
@http_method_dispatcher
class UsersWithId(CORSObject):

    """docstring for UsersWithId"""
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
        pass

    @validate_credentials(verify_token)
    def put(self):
        pass

    @validate_credentials(verify_token)
    def patch(self):
        pass

    @validate_credentials(verify_token)
    def delete(self):
        pass

    # def user_exists(self, id):
    #     if User.object.get(id=id) is None:
    #         return make_error('User does not exist', 404)

    # @check(user_exists)
    # def get(self, id):
    #     return make_ok()

    # @validate_json(user_full.validate)
    # def post(self, id):
    #     input_json = {str(k): str(v) for k, v in request.json.iteritems()}
    #     chain(register_users.s(str(input_json)), send_confirm_email.s()).apply_async()
    #     return make_ok()

    # @check(user_exists)
    # @validate_json(user_partial.validate)
    # def put(self, id):

    #     return make_ok()

    # @check(user_exists)
    # @validate_json(user_partial.validate, default=dict)
    # def patch(self, id):
    #     return make_ok

    # @check(user_exists)
    # def delete(self, id):
    #     return make_ok()
