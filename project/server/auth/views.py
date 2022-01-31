from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User

auth_blueprint = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    # retrieve info of current users in the db

    def get(self):
        # return make_response(jsonify(responseObject)), 201
        ql = User.query.all()
        resultArr = []
        for i in ql:
            responseObject = {
                'admin': i.admin,
                'email': i.email,
                'id': i.id,
                'registered_on': i.registered_on.strftime("%c, %Z"),
            }
            resultArr.append(responseObject)
        string = 'Users: ' + ','.join(str(x) for x in resultArr)
        return string

    def post(self):
        # get the post data
        post_data = request.get_json()
        print(request)
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
           # try:
            user = User(
                email=post_data.get('email'),
                password=post_data.get('password')
            )

            # insert the user
            db.session.add(user)
            db.session.commit()
            # generate the auth token
            auth_token = user.encode_auth_token(user.id)
            print(auth_token)
            responseObject = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token
            }
            return make_response(jsonify(responseObject)), 201
            # except Exception as e:
            #     responseObject = {
            #         'status': 'fail',
            #         'message': 'Some error occurred. Please try again.',
            #     }
            #     return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


# define the API resources
registration_view = RegisterAPI.as_view('register_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST', 'GET']
)

auth_blueprint.add_url_rule(
    '/users/index',
    view_func=registration_view,
    methods=['GET']
)
