OAuthHandler

A subclass of urllib2.BaseHandler that (partially) handles OAuth authentication.
Its basically a wrapper around python-oauth

OAuth authentication is defined in RFC 5849.
It involves a resource consumer, a resource provider and a resource owner.
The protocol allows for the consumer to access resources provided by a provider
on behalf of the owner, without requiring the owner to compromise its credentials.
This is done by asking the owner to authenticate itself to the provider using its
credentials and thereby, generating an access token given to the consumer, granting
it controlled access to the resources.

This class only handles the second part of the authentication process i.e. use the
access token to access controlled resources.

The current implementation is not able to obtain the access token by itself.

Copyright (C) 2013 Tuan-Tu Tran <tuantu.t@gmail.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
