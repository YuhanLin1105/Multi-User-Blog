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


# Helper class to secure the cookie (Should put this in a secret file)
class Helper_cookie:
    secret = 'This is a secret'

    @classmethod
    def make_secure_val(self, val):
        return '%s|%s' % (val, hmac.new(self.secret, val).hexdigest())

    @classmethod
    def check_secure_val(self, secure_val):
        val = secure_val.split('|')[0]
        if secure_val == self.make_secure_val(val):
            return val


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
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
         u = cls.by_name(name)
         if u and Helper_sign.valid_pw(name, pw, u.pw_hash):
             return u


# Comment staff
class PostComment(db.Model):
    """ This is a object model class (PostComment) of the database """
    author = db.ReferenceProperty(User, required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post_id = db.IntegerProperty()
	
    @classmethod
    def by_id(cls, cid):
        """ A classmethod function to get the object (PostComment) by
            post_id(int)
            return None if the object (PostComment) do not exist
        """
        return PostComment.get_by_id(cid)

    def render(self):
        """A function to render the  object (PostComent) to html """
        self._render_text = self.content.replace('\n', '<br>')
        return jinja2_env.get_template('comment.html').render(c=self)


class Post(db.Model):
    """ This is a object model class of the database """
    subject = db.StringProperty(required=True)
    author = db.ReferenceProperty(User, required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    liked = db.IntegerProperty(default=0)
    comment = db.ListProperty(int, default=[])
    
    @classmethod
    def by_id(cls, pid):
        """ A classmethod function to get the Post (object) by
            post_id(int)
            return None if the Post(object) do not exist
        """
        return Post.get_by_id(pid)

    def comment_counter(self):
        """ A function to count the number of comment in Post.comment """
        count = 0
        for i in self.comment:
            count += 1
        return count

    def render(self):
        """A function to render the object (Post) to html """
        self._render_text = self.content.replace('\n', '<br>')
        return jinja2_env.get_template('post.html').render(p=self)


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
        cookie_val = Helper_cookie.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and Helper_cookie.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user:
            self.redirect("/login")
        else:
            func(self, *args, **kwargs)
    return login


# Mainpage handler
class MainPage(Handler):
    @login_required
    def get(self):
        self.redirect('/blog')


# NewPost Handler
class NewPost(Handler):
    @login_required
    def get(self):
        self.render("newpost.html", username=self.user.name)

    @login_required
    def post(self):
        username = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject=subject, content=content, author=self.user)
            p.put()
            self.user.liked.append(p.key().id())
            self.user.put()
            self.redirect('/blog/{}'.format(p.key().id()))
        else:
            error = "subject and content please!"
            self.render("newpost.html", subject=subject, content=content,
                        username=username, error=error)


# FrontPage Handler
class BlogFront(Handler):
    def get(self):
        msg_error = self.request.get('error')
        posts = Post.all().order('-created')
        posts = db.GqlQuery("select * from Post order by created desc limit 10"
                            )
        if self.user:
            self.render("front.html", posts=posts, username=self.user.name,
                        error=msg_error)
        else:
            self.render("front.html", posts=posts, error=msg_error)


# Postpage Handler
class PostPage(Handler):
    def get(self, post_id):
        msg_error = self.request.get('error')
        post = Post.get_by_id(int(post_id))
        if not post:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        c = []
        for comment_id in post.comment:
            c.append(PostComment.by_id(comment_id))

        if self.user:
            self.render("permalink.html", post=post, username=self.user.name,
                        comment=c, error=msg_error)
        else:
            self.render("permalink.html", post=post, comment=c,
                        error=msg_error)

    def post(self, post_id):
        msg_error = "Error: please login!"
        p = Post.by_id(int(post_id))
        if not p:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        content = self.request.get('comment_content')
        comment = []
        username = ''
        if self.user:
            username = self.user.name
            msg_error = "Error: Comment can not be empty!"

        if self.user and content:
            c = PostComment(author=self.user, content=content,
                            post_id=int(post_id))
            c.put()
            p.comment.append(c.key().id())
            p.put()
            msg_error = None

        for comment_id in p.comment:
            comment.append(PostComment.by_id(comment_id))

        self.render("permalink.html", post=p, username=username,
                    comment=comment, error=msg_error)


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

        if not Helper_sign.valid_username(self.username):
            params['error_username'] = "Invalid username."
            have_error = True

        if not Helper_sign.valid_password(self.password):
            params['error_password'] = "Invalid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Passwords didn't match."
            have_error = True

        if not Helper_sign.valid_email(self.email):
            params['error_email'] = "Invalid email."
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
    @login_required
    def get(self, liked_id):
        p = Post.by_id(int(liked_id))
        error = None
        if not p:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        if int(liked_id) not in self.user.liked:
            p.liked += 1
            p.put()
            u = self.user
            u.liked.append(int(liked_id))
            u.put()
        else:
            error = "Error: you can not like this anymore."
        time.sleep(0.5)
        if error:
            self.redirect('/blog?error=' + error)
        else:
            self.redirect('/blog')


# Edit handler
class PostEdit(Handler):
    @login_required
    def get(self, post_id):
        error = None
        username = self.user.name
        p = Post.by_id(int(post_id))
        if not p:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        if self.user.name == p.author.name:
            subject = p.subject
            content = p.content
            self.render("edit-post.html", subject=subject, content=content,
                        username=username)
        else:
            error = "Error: You can only edit your post!"
            self.redirect('/blog?error=' + error)

    @login_required
    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        username = self.user.name
        p = Post.by_id(int(post_id))
        if not p:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        if subject and content:
            p.subject = subject
            p.content = content
            p.put()
            time.sleep(0.5)
            self.redirect('/blog/{}'.format(post_id))
        else:
            error = "Subject and content please!"
            self.render("edit-post.html", subject=subject, content=content,
                        username=username, error=error)


# Delete handler
class PostDelete(Handler):
    @login_required
    def get(self, post_id):
        error = None
        p = Post.by_id(int(post_id))
        if not p:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        if self.user.name == p.author.name:
            p.delete()
            time.sleep(0.5)
            self.redirect('/blog')
        else:
            error = "Error: You can only delete your post!"
            self.redirect('/blog?error={}'.format(error))


# CommentEdit handler
class CommentEdit(Handler):
    @login_required
    def get(self, c_id):
        error = None
        c = PostComment.by_id(int(c_id))
        if not c:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        p_id = c.post_id
        username = self.user.name
        if username == c.author.name:
            content = c.content
            self.render("edit-comment.html", content=content,
                        username=username)
        else:
            error = "Error: You can only edit your comment!"
            self.redirect('/blog/{}?error={}'.format(p_id, error))

    @login_required
    def post(self, c_id):
        content = self.request.get('content')
        username = self.user.name
        c = PostComment.by_id(int(c_id))
        if not c:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        p_id = c.post_id
        if content:
            c.content = content
            c.put()
            time.sleep(0.5)
            self.redirect('/blog/{}'.format(p_id))
        else:
            error = "Content please!"
            self.render("edit-comment.html", username=username, error=error)


# Delete handler
class CommentDelete(Handler):
    @login_required
    def get(self, c_id):
        error = None
        c = PostComment.by_id(int(c_id))
        if not c:
            msg_error = "Error: page is not found!"
            self.redirect('/blog?error=' + msg_error)
            return

        p_id = c.post_id
        username = self.user.name
        p = Post.by_id(p_id)
        if username == c.author.name:
            c.delete()
            p.comment.remove(int(c_id))
            p.put()
            time.sleep(0.5)
            self.redirect('/blog/{}'.format(p_id))
        else:
            error = "Error: You can only delete your comment!"
            self.redirect('/blog/{}?error={}'.format(p_id, error))


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/like/([0-9]+)', Like),
                               ('/edit/([0-9]+)', PostEdit),
                               ('/delete/([0-9]+)', PostDelete),
                               ('/c_edit/([0-9]+)', CommentEdit),
                               ('/c_delete/([0-9]+)', CommentDelete)],
                              debug=True)
