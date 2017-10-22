from handlers import Handler
from utils import login_required, comment_exist, comment_own
from models import PostComment
import time


# CommentEdit handler
class CommentEdit(Handler):
    @login_required
    @comment_exist
    @comment_own
    def get(self, c_id):
        c = PostComment.by_id(int(c_id))
        username = self.user.name
        content = c.content
        self.render("edit-comment.html", content=content, username=username)

    @login_required
    @comment_exist
    @comment_own
    def post(self, c_id):
        content = self.request.get('content')
        username = self.user.name
        c = PostComment.by_id(int(c_id))
        p_id = c.post_id
        if content:
            c.content = content
            c.put()
            time.sleep(0.5)
            self.redirect('/blog/{}'.format(p_id))
        else:
            error = "Content please!"
            self.render("edit-comment.html", username=username, error=error)
