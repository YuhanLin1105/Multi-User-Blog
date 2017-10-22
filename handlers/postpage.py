from handlers import Handler
from models import Post, PostComment
from utils import post_exist, login_required


# Postpage Handler
class PostPage(Handler):
    @post_exist
    def get(self, post_id):
        msg_error = self.request.get('error')
        post = Post.get_by_id(int(post_id))
        c = []
        for comment_id in post.comment:
            c.append(PostComment.by_id(comment_id))

        if self.user:
            self.render("permalink.html", post=post, username=self.user.name,
                        comment=c, error=msg_error)
        else:
            self.render("permalink.html", post=post, comment=c,
                        error=msg_error)

    @login_required
    @post_exist
    def post(self, post_id):
        p = Post.by_id(int(post_id))
        content = self.request.get('comment_content')
        comment = []
        username = self.user.name
        msg_error = "Error: Comment can not be empty!"
        if content:
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
