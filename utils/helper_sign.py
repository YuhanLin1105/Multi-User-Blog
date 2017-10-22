import random
import hashlib
import re

from string import letters


# Helper class to secure and check the info of user
class Helper_sign:
    @classmethod
    def make_salt(self, length=5):
        return ''.join(random.choice(letters) for x in xrange(length))

    @classmethod
    def make_pw_hash(self, name, pw, salt=None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

    @classmethod
    def valid_pw(self, name, password, h):
        salt = h.split(',')[0]
        return h == self.make_pw_hash(name, password, salt)

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

    @classmethod
    def valid_username(self, username):
        return username and self.USER_RE.match(username)

    @classmethod
    def valid_password(self, password):
        return password and self.PASS_RE.match(password)

    @classmethod
    def valid_email(self, email):
        return not email or self.EMAIL_RE.match(email)
