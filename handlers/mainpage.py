from handlers import Handler
from utils import login_required


# Mainpage handler
class MainPage(Handler):
    @login_required
    def get(self):
        self.redirect('/blog')
