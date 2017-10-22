from handlers import Handler
from utils import login_required, post_exist, post_own
from models import Post
import time


# Delete handler
class PostDelete(Handler):
    @login_required
    @post_exist
    @post_own
    def get(self, post_id):
        p = Post.by_id(int(post_id))
        p.delete()
        time.sleep(0.5)
        self.redirect('/blog')
