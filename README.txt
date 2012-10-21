OAuthHandler

An subclass of urllib2.BaseHandler that (partially) handles OAuth authentication.

OAuth authentication is defined in RFC 5849.
It involves a resource consumer, a resource provider and a resource owner.
The protocol allows for the consumer to access resources provided by a provider
on behalf of the owner, without requiring the owner to compromise its credentials.
This is done by asking the owner to authenticate itself to the provider using its
credentials and thereby, generating an access token given to the consumer, granting
it controlled access to the resources.

This class only handles the second part of the authentication process i.e. use the
access token to access controlled resources.

It CANNOT obtain the access token by itself.
