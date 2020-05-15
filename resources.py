from functools import wraps
from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel
from flask_jwt_extended import (get_jti, verify_jwt_in_request_optional, verify_jwt_in_request, create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity)
from flask_jwt_extended import(get_current_user, get_jti, get_raw_jwt, set_access_cookies)
from flask_jwt_extended.view_decorators import _decode_jwt_from_request
from flask_jwt_extended.exceptions import NoAuthorizationError
# from flask_jwt_extended.get_jti import _get_jti
# from flask_jwt_extended.get_raw_jwt import _get_raw_jwt
# from flask_jwt_extended.encode_key_loader import _encode_key_loader
from jwt import decode

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}
        
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'message': 'Something went wrong'}, 500

class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])

            # # Set the JWT cookies in the response
            # resp = jsonify({'login': True})
            # set_access_cookies(resp, access_token)

            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}

class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500

class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500

class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}

class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()

class SecretResource(Resource):
    @jwt_required
    def get(self):
        import pdb
        pdb.set_trace()
        current_user = get_jwt_identity()
        jwt_data = _decode_jwt_from_request(request_type='access')

        cookies = ""#_decode_jwt_from_request(request_type='cookies')
        query_string =""# _decode_jwt_from_request(request_type='query_string')
        headers = ""#_decode_jwt_from_request(request_type='headers')
        json = ""#_decode_jwt_from_request(request_type='json')
        
        test = verify_jwt_in_request()
        test2 = verify_jwt_in_request_optional()   
        # test3 = _encode_key_loader()
        return {
            'Welcome': jwt_data, 
            'verify_jwt_in_request' : test, 
            'verify_jwt_in_request_optional' : test2,
            'cookies': cookies,
            'query_string': query_string,
            'headers': headers,
            'json': json,
            'username': username,
            'password': json,
        }

# def custom_validator(view_function):
#     @wraps(view_function)
#     def wrapper(*args, **kwargs):
#         jwt_data = _decode_jwt_from_request(request_type='access')
        
#         # Do your custom validation here.
#         if (True):
#             authorized = True
#         else:
#             authorized = False

#         if not authorized:
#             raise NoAuthorizationError("Explanation goes here")

#         return view_function(*args, **kwargs)

#     return jwt_required(wrapper)