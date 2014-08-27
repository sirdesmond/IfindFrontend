from flask import Blueprint, request
from schema import (Schema, Optional)
from celery import chain
from models import (User, user_full, user_partial)
from tasks import (tasks)
from lib import *

blueprint = Blueprint(__name__, __name__)


@blueprint.route('', methods=['GET', 'DELETE'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class Users(object):
    def get(self):
        user_database.reset()
        return make_ok


@blueprint.route('/<id>', methods=['GET', 'PATCH', 'POST', 'PUT', 'DELETE'])
# @check(url_id_matches_body)
@http_method_dispatcher
class UsersWithId(object):
    """docstring for UserWithName"""

    def user_exists(self, id):
        if User.object.get(id=id) is None:
            return make_error('User does not exist', 404)

    @check(user_exists)
    def get(self, id):
        return make_ok()

    @validate_json(user_full.validate)
    def post(self, id):
        input_json = {str(k): str(v) for k, v in request.json.iteritems()}
        chain(register_users.s(str(input_json)), send_confirm_email.s()).apply_async()
        return make_ok()

    @check(user_exists)
    @validate_json(user_partial.validate)
    def put(self, id):

        return make_ok()

    @check(user_exists)
    @validate_json(user_partial.validate, default=dict)
    def patch(self, id):
        return make_ok

    @check(user_exists)
    def delete(self, id):
        return make_ok()