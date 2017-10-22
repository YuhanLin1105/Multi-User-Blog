from handlers import Handler


# Logout handler
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')
