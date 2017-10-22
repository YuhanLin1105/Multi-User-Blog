from handlers import Handler
from models import Post
from google.appengine.ext import db


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