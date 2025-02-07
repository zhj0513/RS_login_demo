from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask import request, jsonify, current_app
from app.models import User
from functools import wraps

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256')

def verify_password(hashed_password, password):
    return check_password_hash(hashed_password, password)

def generate_token(username):
    return jwt.encode({'sub': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
                      current_app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': '请求未包含token!'}), 401
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(username=data['sub']).first()
            if not current_user:
                return jsonify({'message': '用户不存在!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'token过期!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': '无效的token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated
