import urllib2
import urlparse

class AbstractOAuthHandler:
    # OAuth authentication is specified in RFC 5849.

    def __init__(self, passwd=None):
        if passwd is None:
            passwd = HTTPPasswordMgr()
        self.passwd = passwd
        self.add_password = self.passwd.add_password
        self.retried = 0
        self.nonce_count = 0
        self.last_nonce = None

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
            raise HTTPError(req.get_full_url(), 401, "OAuth auth failed",
                            headers, None)
        else:
            self.retried += 1
        if authreq:
            scheme = authreq.split()[0]
            if scheme.lower() == 'oauth':
                return self.retry_http_oauth_auth(req, authreq)

    def retry_http_oauth_auth(self, req, auth):
	return
        token, challenge = auth.split(' ', 1)
        chal = parse_keqv_list(parse_http_list(challenge))
        auth = self.get_authorization(req, chal)
        if auth:
            auth_val = 'Digest %s' % auth
            if req.headers.get(self.auth_header, None) == auth_val:
                return None
            req.add_unredirected_header(self.auth_header, auth_val)
            resp = self.parent.open(req, timeout=req.timeout)
            return resp

    def get_cnonce(self, nonce):
        # The cnonce-value is an opaque
        # quoted string value provided by the client and used by both client
        # and server to avoid chosen plaintext attacks, to provide mutual
        # authentication, and to provide some message integrity protection.
        # This isn't a fabulous effort, but it's probably Good Enough.
        dig = hashlib.sha1("%s:%s:%s:%s" % (self.nonce_count, nonce, time.ctime(),
                                            randombytes(8))).hexdigest()
        return dig[:16]

    def get_authorization(self, req, chal):
        try:
            realm = chal['realm']
            nonce = chal['nonce']
            qop = chal.get('qop')
            algorithm = chal.get('algorithm', 'MD5')
            # mod_digest doesn't send an opaque, even though it isn't
            # supposed to be optional
            opaque = chal.get('opaque', None)
        except KeyError:
            return None

        H, KD = self.get_algorithm_impls(algorithm)
        if H is None:
            return None

        user, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if user is None:
            return None

        # XXX not implemented yet
        if req.has_data():
            entdig = self.get_entity_digest(req.get_data(), chal)
        else:
            entdig = None

        A1 = "%s:%s:%s" % (user, realm, pw)
        A2 = "%s:%s" % (req.get_method(),
                        # XXX selector: what about proxies and full urls
                        req.get_selector())
        if qop == 'auth':
            if nonce == self.last_nonce:
                self.nonce_count += 1
            else:
                self.nonce_count = 1
                self.last_nonce = nonce

            ncvalue = '%08x' % self.nonce_count
            cnonce = self.get_cnonce(nonce)
            noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, qop, H(A2))
            respdig = KD(H(A1), noncebit)
        elif qop is None:
            respdig = KD(H(A1), "%s:%s" % (nonce, H(A2)))
        else:
            # XXX handle auth-int.
            raise URLError("qop '%s' is not supported." % qop)

        # XXX should the partial digests be encoded too?

        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (user, realm, nonce, req.get_selector(),
                                  respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if entdig:
            base += ', digest="%s"' % entdig
        base += ', algorithm="%s"' % algorithm
        if qop:
            base += ', qop=auth, nc=%s, cnonce="%s"' % (ncvalue, cnonce)
        return base

    def get_algorithm_impls(self, algorithm):
        # algorithm should be case-insensitive according to RFC2617
        algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if algorithm == 'MD5':
            H = lambda x: hashlib.md5(x).hexdigest()
        elif algorithm == 'SHA':
            H = lambda x: hashlib.sha1(x).hexdigest()
        # XXX MD5-sess
        KD = lambda s, d: H("%s:%s" % (s, d))
        return H, KD

    def get_entity_digest(self, data, chal):
        # XXX not implemented yet
        return None


class OAuthHandler(urllib2.BaseHandler, AbstractOAuthHandler):
    """An authentication protocol defined by RFC 5849"""

    auth_header = 'Authorization'

    def http_error_401(self, req, fp, code, msg, headers):
        host = urlparse.urlparse(req.get_full_url())[1]
        retry = self.http_error_auth_reqed('www-authenticate',
                                           host, req, headers)
        self.reset_retry_count()
        return retry


