import urllib2
import urlparse
import oauth.oauth as oauth

class AbstractOAuthHandler:
	# OAuth authentication is specified in RFC 5849.

	def __init__(self, consumer, access_token, signature_method=None):
		self.consumer=consumer
		self.access_token=access_token
		if signature_method==None:
			signature_method=oauth.OAuthSignatureMethod_HMAC_SHA1()
		self.signature_method=signature_method
		self.retried = 0

	def reset_retry_count(self):
		self.retried = 0

	def http_error_auth_reqed(self, auth_header, host, req, headers):
		authreq = headers.get(auth_header, None)
		if self.retried > 5:
			# Don't fail endlessly - if we failed once, we'll probably
			# fail a second time. Hm. Unless the Password Manager is
			# prompting for the information. Crap. This isn't great
			# but it's better than the current 'repeat until recursion
			# depth exceeded' approach <wink>
			raise HTTPError(req.get_full_url(), 401, "OAuth auth failed", headers, None)
		else:
			self.retried += 1
		if authreq:
			scheme = authreq.split()[0]
			if scheme.lower() == 'oauth':
				return self.retry_http_oauth_auth(req, authreq)

	def retry_http_oauth_auth(self, req, auth):
		return

class OAuthHandler(urllib2.BaseHandler, AbstractOAuthHandler):
	"""An authentication protocol defined by RFC 5849"""

	auth_header = 'Authorization'

	def http_error_401(self, req, fp, code, msg, headers):
		host = urlparse.urlparse(req.get_full_url())[1]
		retry = self.http_error_auth_reqed('www-authenticate', host, req, headers)
		self.reset_retry_count()
		return retry


