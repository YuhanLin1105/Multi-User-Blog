import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# Templates directory
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# Jinja2 environment
jinja2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)
# secure the cookie (Should put this in a secret file)
secret = 'This is a secret'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# The parent class for all handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kw):
        t = jinja2_env.get_template(template)
        return t.render(kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    # If True and True return cookie_val ; If not True and Ture return False

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# The mainpage handler
class MainPage(Handler):
    def get(self):
        self.redirect('/blog')

# Do not understand the effect of the blog_key here
# def blog_key(name='default'):
#     return db.Key.from_path('blogs', name)


# Post staff
class Post(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    liked = db.IntegerProperty(default=0)
    comment = db.ListProperty(int, default=[])

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid)

    def comment_counter(self):
        count = 0
        for i in self.comment:
            count += 1
        return count

    def render(self):
        # Make '\n' work in html
        self._render_text = self.content.replace('\n', '<br>')
        return jinja2_env.get_template('post.html').render(p=self)


# Comment staff
class PostComment(db.Model):
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, cid):
        return PostComment.get_by_id(cid)

    def render(self):
        # Make '\n' work in html
        self._render_text = self.content.replace('\n', '<br>')
        return jinja2_env.get_template('comment.html').render(c=self)



# User staff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# def users_key(group = 'default'):
#     return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    liked = db.ListProperty(int, default=[])

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# NewPost Handler
class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html", username=self.user.name)
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # Do not understand the effect of the parent here
            # p = Post(parent=blog_key(), subject=subject, content=content)
            p = Post(subject=subject, content=content, author=self.user.name)
            p.put()
            self.user.liked.append(p.key().id())
            self.user.put()
            self.redirect('/blog/{}'.format(p.key().id()))
            # self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


# Frontpage Handler
class BlogFront(Handler):
    def get(self):
        msg_error = self.request.get('error')
        posts = Post.all().order('-created')
        posts = db.GqlQuery("select * from Post order by created desc limit 10"
                            )
        if self.user:
            self.render("front.html", posts=posts, username=self.user.name, error=msg_error)
        else:
            self.render("front.html", posts=posts, error=msg_error)


# Postpage Handler
class PostPage(Handler):
    def get(self, post_id):
        # Do not understand the effect of the parent here
        # key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = []
        for comment_id in post.comment:
            c.append(PostComment.by_id(comment_id))

        if self.user:
            self.render("permalink.html", post=post, username=self.user.name, comment=c)
        else:
            self.render("permalink.html", post=post, comment=c)

    def post(self, post_id):
        error = "Error: please login!"
        p = Post.by_id(int(post_id))
        content = self.request.get('comment_content')
        comment = []
        username = ''
        if self.user:
            username = self.user.name
            error = "Error: Comment can not be empty!"
        if self.user and content:
            c = PostComment(author=self.user.name, content=content)
            c.put()
            p.comment.append(c.key().id())
            p.put()
            error = None

        for comment_id in p.comment:
            comment.append(PostComment.by_id(comment_id))

        self.render("permalink.html", post=p, username=username, comment=comment, error=error)



# User signup-info check
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Signup handler
class Signup(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# Register Handler
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


# Login handler
class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


# Logout handler
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')


# Like handler
class Like(Handler):
    def get(self, liked_id):
        error = None
        if self.user:
            if int(liked_id) not in self.user.liked:
                p = Post.by_id(int(liked_id))
                p.liked += 1
                p.put()

                u = self.user
                u.liked.append(int(liked_id))
                u.put()
            else:
                error = "Error: you can not like this anymore."
        else:
            error = "Error: please login."
        time.sleep(0.5)
        if error:
            self.redirect('/blog?error=' + error)
        else:
            self.redirect('/blog')


# Comment handler
# class Comment(Handler):
#     def get(self, post_id):
#         error = None
#         if self.user:
#             self.render("comment.html", username=self.user.name)







app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/like/([0-9]+)', Like)],
                                debug=True)

