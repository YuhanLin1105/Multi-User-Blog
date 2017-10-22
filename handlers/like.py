import time
from handlers import Handler
from models import Post
from utils import login_required, post_exist, like_available


# Like handler
class Like(Handler):
    @login_required
    @post_exist
    @like_available
    def get(self, liked_id):
        p = Post.by_id(int(liked_id))
        p.liked += 1
        p.put()
        u = self.user
        u.liked.append(int(liked_id))
        u.put()
        time.sleep(0.5)
        self.redirect('/blog')
