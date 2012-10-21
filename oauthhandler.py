import urllib2

class OAuthHandler(urllib2.BaseHandler, AbstractOAuthHandler):
    """An authentication protocol defined by RFC 5849"""

    auth_header = 'Authorization'

    def http_error_401(self, req, fp, code, msg, headers):
        host = urlparse.urlparse(req.get_full_url())[1]
        retry = self.http_error_auth_reqed('www-authenticate',
                                           host, req, headers)
        self.reset_retry_count()
        return retry


