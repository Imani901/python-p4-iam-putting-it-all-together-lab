#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):  
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        errors = []

        if not username or not username.strip():
            errors.append("Username is required.")
        if not password or len(password.strip()) < 6:
            errors.append("Password must be at least 6 characters.")

        if errors:
            return {"errors": errors}, 422  

        try:
            new_user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            new_user.password_hash = password

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return {
                "id": new_user.id,
                "username": new_user.username,
                "image_url": new_user.image_url,
                "bio": new_user.bio
            }, 201

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username already taken."]}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        if user:
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        else:
            return {"error": "User not found"}, 404


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id

            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200

        return {"errors": ["Invalid username or password"]}, 401


class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return '', 204

        return {"error": "Unauthorized"}, 401


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return {"error": "Unauthorized"}, 401

        recipes = Recipe.query.all()

        recipe_list = []
        for recipe in recipes:
            recipe_list.append({
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            })

        return recipe_list, 200

    def post(self):
        user_id = session.get('user_id')

        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes = data.get('minutes_to_complete')

        try:
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes,
                user_id=user_id
            )

            db.session.add(new_recipe)
            db.session.commit()

            return {
                "id": new_recipe.id,
                "title": new_recipe.title,
                "instructions": new_recipe.instructions,
                "minutes_to_complete": new_recipe.minutes_to_complete,
                "user": {
                    "id": new_recipe.user.id,
                    "username": new_recipe.user.username,
                    "image_url": new_recipe.user.image_url,
                    "bio": new_recipe.user.bio
                }
            }, 201

        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


# Register endpoints
api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RecipeIndex, '/recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
