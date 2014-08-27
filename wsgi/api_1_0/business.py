from flask import (Blueprint, request)
from models import User
from lib import (check, http_method_dispatcher,
                 if_content_exists_then_is_json, validate_credentials, CORSObject)

blueprint = Blueprint(__name__, __name__)