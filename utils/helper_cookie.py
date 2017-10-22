import hmac


class Helper_cookie:
    secret = 'This is a secret'

    @classmethod
    def make_secure_val(self, val):
        return '%s|%s' % (val, hmac.new(self.secret, val).hexdigest())

    @classmethod
    def check_secure_val(self, secure_val):
        val = secure_val.split('|')[0]
        if secure_val == self.make_secure_val(val):
            return val
