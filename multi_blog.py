import webapp2

from handlers import MainPage, BlogFront, NewPost, PostPage, Register
from handlers import Login, Logout, Like, PostEdit, PostDelete, CommentEdit
from handlers import CommentDelete


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
