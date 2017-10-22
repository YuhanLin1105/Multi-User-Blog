from google.appengine.ext import db
from models import User
from utils import jinja2_env


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
