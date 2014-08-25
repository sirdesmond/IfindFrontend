from flask import jsonify


def unauthorized(message):
	response ={}
	response["error"]='unauthorized'
	response["message"]=message
	response["status"] = 401
	return response


def forbidden(message):
	response={}
	response["error"]='forbidden'
	response["message"]=message
	response["status"] = 403
	return response
