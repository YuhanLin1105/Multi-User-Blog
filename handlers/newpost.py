from handlers import Handler
from utils import login_required
from models import Post


# NewPost Handler
class NewPost(Handler):
    @login_required
    def get(self):
        self.render("newpost.html", username=self.user.name)

    @login_required
    def post(self):
        username = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject=subject, content=content, author=self.user)
            p.put()
            self.user.liked.append(p.key().id())
            self.user.put()
            self.redirect('/blog/{}'.format(p.key().id()))
        else:
            error = "subject and content please!"
            self.render("newpost.html", subject=subject, content=content,
                        username=username, error=error)
