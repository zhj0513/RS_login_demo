from flask import Blueprint, request, jsonify
from .models import db, User
from .auth import hash_password, verify_password, generate_token

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    new_user = User(username=data['username'], password=hash_password(data['password']))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not verify_password(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = generate_token(user.username)
    return jsonify({'access_token': token})
