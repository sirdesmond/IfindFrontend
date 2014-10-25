from flask import Blueprint, request, g
from celery import chain
from models.user import (User, user_full, user_profile_partial, user_full_with_hash)
from tasks.tasks import (register_user, send_confirm_email,
                         confirm_user, add_contact)
from flask.ext.cors import cross_origin
import json
import time
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials,
                 CORSObject, make_ok, make_ok_user, make_error, validate_json)
from bson.objectid import ObjectId
import pdb

blueprint = Blueprint(__name__, __name__)


@blueprint.route('', methods=['POST', 'DELETE', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class Users(CORSObject):

    @validate_json(user_full_with_hash.validate)
    def post(self):
        response = {}
        data = request.json['data']

        input_json = {str(k): str(v) for k, v in data.iteritems()}
        user = User()
        user.json_to_doc(json_data=input_json)
        input_json = user.to_json(with_hash=True)
        print "This is the user being processed :" + str(input_json)
        new_user = str(input_json)
        result = chain(register_user.s(new_user),
                       send_confirm_email.s()).apply_async()
        response['message'] = 'Registration submitted successfully'

        return make_ok(user=user.to_json())

    def delete(self):
        if False:
            user_database.reset()
            return make_ok(reponse=reponse)

""" RESOURCE FOR LOGGED IN USER REPRESENTED BY 'ME' """


@blueprint.route('/me', methods=['POST', 'DELETE', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class RequestingUser(CORSObject):

    @validate_json(user_full_with_hash.validate)
    def put(self):
        pass

    def delete(self):
        pass


@blueprint.route('/me/contacts', methods=['POST', 'DELETE', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class RequestingUserContacts(CORSObject):

    """docstring for UsersWithId"""
    def verify_token(*args, **kwargs):
        try:
            token = str(request.headers).split(
                'Authorization: Basic ')[1].split('\r')[0]
            user = User.verify_auth_token(token)

            if not user:
                added_headers = None
                return make_error('Invalid token', 401,
                                  additional_headers=added_headers)

            g.current_user = user
            return None

        except Exception, e:
            return make_error(str(e), 401)

    @validate_json(user_full_with_hash.validate)
    def put(self, id):
        pass

    @validate_credentials(verify_token)
    @validate_json(user_profile_partial.validate)
    def post(self):
        pdb.set_trace
        data = request.json["data"]

        _id = ObjectId(data["id"])
        print type(_id)
        user = User.objects.get(_id=_id)

        if user is not None:
            print 'successfully Got user'
            result = add_contact.apply_async(
                ("",), {"user": g.current_user.email,
                        "contact": user.email})
            print result
            return make_ok(status='ok')

        return make_error()

    def delete(self, id):
        pass


@blueprint.route('/mngr/<controller>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
# @check(url_id_matches_body)
@http_method_dispatcher
class UsersManager(CORSObject):

    """docstring for UsersWithId"""
    def verify_token(*args, **kwargs):
        try:
            token = str(request.headers).split(
                'Authorization: Basic ')[1].split('\r')[0]
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

    # @validate_credentials(verify_token)
    def put(self, controller):

        data = request.json
        update = {}
        input_json = {str(k): str(v) for k, v in data.iteritems()}

        if str(controller) == 'activate':
            user = User.objects.get(email=input_json.get("email"))
            v_status = user["v_status"]
            '''
            retrieve the users v_status compare submitted code to the actual if
            success call the confirm, if not send no good request.
            '''
            isconfirmed = False
            for key in {'vcode', 'vcode_exp', 'verified'}:
                if key not in v_status:
                    make_error("Bad Request", 401)

            if not v_status["verified"] and v_status["vcode_exp"] > time.time():

                if v_status["vcode"] == input_json.get("code"):
                    isconfirmed = True

            if isconfirmed:

                confirm_user.delay(str(user.email))

                return make_ok(response="Success")

    @validate_credentials(verify_token)
    def patch(self):
        pass

    @validate_credentials(verify_token)
    def delete(self):
        pass


@blueprint.route('/<id>', methods=['PUT', 'GET', 'DELETE', 'OPTIONS'])
@cross_origin(origins='*', headers=['Authorization', 'Content-Type'])
@check(if_content_exists_then_is_json)
@http_method_dispatcher
class UserWithId(CORSObject):

    """docstring for UsersWithId"""
    def verify_token(*args, **kwargs):
        try:
            token = str(request.headers).split(
                'Authorization: Basic ')[1].split('\r')[0]

            user = User.verify_auth_token(token)

            if not user:
                added_headers = None
                print 'bad token'
                return make_error('Invalid token', 401,
                                  additional_headers=added_headers)

            g.current_user = user
            return None

        except Exception, e:
            print str(e)
            return make_error(str(e), 401)

    @validate_json(user_full_with_hash.validate)
    def put(self):
        pass

    #@check()
    @validate_credentials(verify_token)
    def get(self, id):
        response = {}
        try:
            user = User.objects.get(id=id)
            pass
        except Exception, e:
            print str(e)
            raise e

        user_json = user.to_json(_type=1) if user else None
        print "Got User"
        print user_json
        return make_ok_user(user=user_json)

    def delete(self):
        if False:
            user_database.reset()
            return make_ok(reponse=reponse)

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
