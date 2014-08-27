from ifindapp import app
from api_1_0 import (user, business, auth)

# Attach blueprints.
app.register_blueprint(user.blueprint, url_prefix='/api/v1.0/user')
app.register_blueprint(auth.blueprint, url_prefix='/api/v1.0/auth')
app.register_blueprint(business.blueprint, url_prefix='/api/v1.0/bus')
