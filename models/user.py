from utils import Helper_sign
from google.appengine.ext import db


# User staff
class User(db.Model):
    """ This is a object model class (User) of the database """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    liked = db.ListProperty(int, default=[])

    @classmethod
    def by_id(cls, uid):
        """ A classmethod function to get the object (user) by
            post_id(int)
            return None if the object (User) do not exist
        """
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        """ A classmethod function to get the object (user) by
            name(str)
            return None if the object (User) do not exist
        """
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """ A classmethod function to create the object (user) """
        pw_hash = Helper_sign.make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and Helper_sign.valid_pw(name, pw, u.pw_hash):
            return u
