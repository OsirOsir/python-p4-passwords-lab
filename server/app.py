#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        # Create new user with hashed password
        user = User(username=username)
        user.password_hash = password  # Password hashing occurs in the model's setter

        # Save the user to the database
        db.session.add(user)
        db.session.commit()

        # Store user ID in session
        session['user_id'] = user.id

        return user.to_dict(), 201


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        
        return {}, 204


class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        # Find user by username
        user = User.query.filter_by(username=username).first()

        # Authenticate user with provided password
        if user and user.authenticate(password):
            # Store user ID in session
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        # Remove user ID from session
        session.pop('user_id', None)
        
        return {}, 204

        

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)