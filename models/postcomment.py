from google.appengine.ext import db
from models import User
from utils import jinja2_env


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