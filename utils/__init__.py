from helper_sign import Helper_sign
from helper_cookie import Helper_cookie

import jinja2
import os
from functools import wraps
from google.appengine.ext import db


# Templates directory
template_dir = os.path.join(os.path.abspath('.'), 'templates')
# Jinja2 environment
jinja2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)


def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if self.user:
            func(self, *args, **kwargs)
        else:
            self.redirect("/login")
    return wrapper


def post_exist(func):
    @wraps(func)
    def wrapper(self, post_id, *args, **kwargs):
        key = db.Key.from_path('Post', int(post_id))
        p = db.get(key)
        if p:
            return func(self, post_id)
        else:
            self.error(404)
            return
    return wrapper


def post_own(func):
    @wraps(func)
    def wrapper(self, post_id, *args, **kwargs):
        key = db.Key.from_path('Post', int(post_id))
        p = db.get(key)
        if p.author.name == self.user.name:
            return func(self, post_id)
        else:
            error = "Error: You can only edit/delete your post!"
            self.redirect('/blog?error=' + error)
            return
    return wrapper


def comment_exist(func):
    @wraps(func)
    def wrapper(self, c_id, *args, **kwargs):
        key = db.Key.from_path('PostComment', int(c_id))
        c = db.get(key)
        if c:
            return func(self, c_id)
        else:
            self.error(404)
            return
    return wrapper


def comment_own(func):
    @wraps(func)
    def wrapper(self, c_id, *args, **kwargs):
        key = db.Key.from_path('PostComment', int(c_id))
        c = db.get(key)
        if c.author.name == self.user.name:
            return func(self, c_id)
        else:
            error = "Error: You can only edit/delete your comment!"
            self.redirect('/blog?error=' + error)
            return
    return wrapper


def like_available(func):
    @wraps(func)
    def wrapper(self, p_id, *args, **kwargs):
        if int(p_id) in self.user.liked:
            error = "Error: you can not like this anymore."
            self.redirect('/blog?error=' + error)
            return
        else:
            return func(self, p_id)
    return wrapper
