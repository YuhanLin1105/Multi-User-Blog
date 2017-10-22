from handlers import Handler
from utils import login_required, post_exist, post_own
from models import Post
import time


# Edit handler
class PostEdit(Handler):
    @login_required
    @post_exist
    @post_own
    def get(self, post_id):
        username = self.user.name
        p = Post.by_id(int(post_id))
        subject = p.subject
        content = p.content
        self.render("edit-post.html", subject=subject, content=content,
                    username=username)

    @login_required
    @post_exist
    @post_own
    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        username = self.user.name
        p = Post.by_id(int(post_id))
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
