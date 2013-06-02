import urllib
import urllib2
import urlparse
import oauth.oauth as oauth
import ConfigParser

class TokenHelper:
	def __init__(self, consumer_key, consumer_secret, signature_method=None):
		self.consumer=oauth.OAuthConsumer(consumer_key, consumer_secret)
		if signature_method==None:
			signature_method=oauth.OAuthSignatureMethod_HMAC_SHA1()
		self.signature_method=signature_method
		self.__opener=urllib2.build_opener()
	
	def get_request_token(self, request_token_url, callback_url=None, request_token_method="POST"):
		http_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, callback=callback_url, http_url=request_token_url, http_method=request_token_method)
		http_request.sign_request(self.signature_method, self.consumer, "")
		return self.__get_token_from_signed_request(http_request)

	def get_authentication_url(self, authentication_url, request_token):
		url_parts=urlparse.urlparse(authentication_url)
		params=dict(urlparse.parse_qsl(url_parts.query))
		params["oauth_token"]=request_token.key
		url_parts=list(url_parts)
		url_parts[4]=urllib.urlencode(params)
		return urlparse.urlunparse(url_parts)
	
	def get_access_token(self, access_token_url, verifier, request_token, access_token_method="POST"):
		http_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, http_url=access_token_url, token=request_token, http_method=access_token_method)
		http_request.parameters["oauth_verifier"]=verifier
		http_request.sign_request(self.signature_method, self.consumer, request_token)
		return self.__get_token_from_signed_request(http_request)

	@staticmethod
	def get_access_token_from_file(filename, section="OAuth", key="access_token_key", secret="access_token_secret"):
		config=ConfigParser.RawConfigParser()
		config.read([filename])
		if config.has_option(section,key) and config.has_option(section, secret):
			return oauth.OAuthToken(config.get(section, key), config.get(section, secret))

	@staticmethod
	def save_access_token_to_file(access_token, filename, section="OAuth", key="access_token_key", secret="access_token_secret"):
		config=ConfigParser.RawConfigParser()
		if not config.has_section(section):
			config.add_section(section)
		config.set(section, key, access_token.key)
		config.set(section, secret, access_token.secret)
		with open(filename,"w") as out:
			config.write(out)

	def get_access_token_from_console(self, request_token_url, authentication_url, access_token_url, callback=None):
		"""
		Ask the user to open an url to authenticate to provider and then copy paste the verifier code in the console
		"""
		request_token=self.get_request_token(request_token_url, callback)

		url = self.get_authentication_url(authentication_url, request_token)

		print "Go to:"
		print
		print url
		print
		print "login and then copy/paste the code here"
		verifier=raw_input()

		access_token=self.get_access_token(access_token_url, verifier, request_token)
		return access_token

	def __get_token_from_signed_request(self, http_request):
		if http_request.http_method=="POST":
			data={}
		else:
			data=None
		resp=self.__opener.open(urllib2.Request(http_request.http_url, data, http_request.to_header()))
		content=resp.read()
		resp.close()
		token=oauth.OAuthToken.from_string(content)
		return token


class AbstractOAuthHandler:
	# OAuth authentication is specified in RFC 5849.

	def __init__(self, consumer=None, access_token=None, signature_method=None):
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
			return None
		else:
			self.retried += 1
		if authreq:
			scheme = authreq.split()[0]
			if scheme.lower() == 'oauth':
				return self.retry_http_oauth_auth(req, authreq)

	def retry_http_oauth_auth(self, req, auth):
		#build the signed authorization header from consumer and access_token
		oauth_request=oauth.OAuthRequest.from_consumer_and_token(
			oauth_consumer=self.consumer,
			token=self.access_token,
			http_url=req.get_full_url(),
			http_method=req.get_method(),
		)

		#add parameters from post data
		if req.has_data():
			data=dict(urlparse.parse_qsl(req.data))
			oauth_request.parameters.update(data)

		#add parameters from query string
		query_string=urlparse.urlparse(req.get_full_url()).query
		data=dict(urlparse.parse_qsl(query_string))
		oauth_request.parameters.update(data)

		#sign request
		oauth_request.sign_request(self.signature_method, self.consumer, self.access_token)

		#add authorization header
		auth = oauth_request.to_header()[self.auth_header]
		if req.headers.get(self.auth_header, None) == auth:
			return None
		req.add_unredirected_header(self.auth_header, auth)

		#open request
		return self.parent.open(req, timeout=req.timeout)

class OAuthHandler(urllib2.BaseHandler, AbstractOAuthHandler):
	"""An authentication protocol defined by RFC 5849"""

	auth_header = 'Authorization'

	def http_error_401(self, req, fp, code, msg, headers):
		host = urlparse.urlparse(req.get_full_url())[1]
		retry = self.http_error_auth_reqed('www-authenticate', host, req, headers)
		self.reset_retry_count()
		return retry


