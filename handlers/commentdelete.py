from handlers import Handler
from utils import login_required, comment_exist, comment_own
from models import PostComment, Post
import time


# Delete handler
class CommentDelete(Handler):
    @login_required
    @comment_exist
    @comment_own
    def get(self, c_id):
        c = PostComment.by_id(int(c_id))
        p_id = c.post_id
        p = Post.by_id(p_id)
        c.delete()
        p.comment.remove(int(c_id))
        p.put()
        time.sleep(0.5)
        self.redirect('/blog/{}'.format(p_id))
