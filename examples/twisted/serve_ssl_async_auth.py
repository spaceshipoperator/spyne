#!/usr/bin/env python
#encoding: utf8
#
# Copyright © Burak Arslan <burak at arskom dot com dot tr>,
#             Arskom Ltd. http://www.arskom.com.tr
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the owner nor the names of its contributors may be
#       used to endorse or promote products derived from this software without
#       specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""
assuming you have created a server.pem as follows:

   $ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX -nodes
   $ ( openssl x509 -in cert.pem; cat key.pem ) > server.pem

"""
import logging
import hashlib
import random
import sys

# bcrypt seems to be among the latest consensus around cryptograpic circles on
# storing passwords.
# You need the package from http://code.google.com/p/py-bcrypt/
# You can install it by running easy_install py-bcrypt.
try:
    import bcrypt
except ImportError:
    print('easy_install --user py-bcrypt to get it.')
    raise

from spyne.application import Application
from spyne.decorator import srpc, rpc
from spyne.error import ArgumentError
from spyne.error import ResourceNotFoundError
from spyne.model.complex import ComplexModel
from spyne.model.fault import Fault
from spyne.model.primitive import Mandatory, String, Unicode
from spyne.protocol.soap import Soap11
from spyne.service import ServiceBase

from twisted.internet import reactor, ssl
from twisted.web.server import Site
from twisted.internet.task import deferLater
from twisted.python.modules import getModule

from spyne.server.twisted import TwistedWebResource

HOST = sys.argv[1] # 0.0.0.0
PORT = sys.argv[2] # 8000
NS = sys.argv[3] # localhost.localdomain
SSL = sys.argv[4] # ssl

class AuthenticationError(Fault):
    __namespace__ = NS

    def __init__(self, user_name):
        # TODO: self.transport.http.resp_code = HTTP_401

        super(AuthenticationError, self).__init__(
                faultcode='Client.AuthenticationError',
                faultstring='Invalid authentication request for %r' % user_name
            )


class AuthorizationError(Fault):
    __namespace__ = NS

    def __init__(self):
        # TODO: self.transport.http.resp_code = HTTP_401

        super(AuthorizationError, self).__init__(
                faultcode='Client.AuthorizationError',
                faultstring='You are not authozied to access this resource.'
            )


class RequestHeader(ComplexModel):
    __namespace__ = NS

    session_id = Mandatory.String
    user_name = Mandatory.String


user_db = {
    'neo': bcrypt.hashpw('Wh1teR@bbit', bcrypt.gensalt()),
}

session_db = set()

class AuthenticationService(ServiceBase):
    __tns__ = NS

    @srpc(Mandatory.String, Mandatory.String, _returns=String,
                                                    _throws=AuthenticationError)
    def authenticate(user_name, password):
        password_hash = user_db.get(user_name, None)

        if password_hash is None:
           raise AuthenticationError(user_name)

        if bcrypt.hashpw(password, password_hash) == password_hash:
            session_id = (user_name, '%x' % random.randint(1<<124, (1<<128)-1))
            session_db.add(session_id)
        else:
           raise AuthenticationError(user_name)

        return session_id[1]

def validate_clob(client_md5sum, clob):
    local_md5sum = hashlib.md5(clob.encode("utf-8")).hexdigest()
    return(local_md5sum == client_md5sum)

class ClobRqService(ServiceBase):
    __tns__ = NS
    __in_header__ = RequestHeader

    @rpc(Unicode, Unicode, _returns=Unicode)
    def enqueue_clob(ctx, md5sum, clob):
        """

        """
        def _cb():
            if validate_clob(md5sum, clob):
                result = "do the needful!"
            else:
                result = "nuts!"

            return result

        return deferLater(reactor, 0.5, _cb)


def _on_method_call(ctx):
    if ctx.in_object is None:
        raise ArgumentError("RequestHeader is null")
    if not (ctx.in_header.user_name, ctx.in_header.session_id) in session_db:
        raise AuthenticationError(ctx.in_object.user_name)

ClobRqService.event_manager.add_listener('method_call', _on_method_call)

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('spyne.protocol.xml').setLevel(logging.DEBUG)
    logging.getLogger('twisted').setLevel(logging.DEBUG)

    application = Application([AuthenticationService,ClobRqService],
        tns=NS,
        in_protocol=Soap11(validator='lxml'),
        out_protocol=Soap11()
    )

    resource = TwistedWebResource(application)

    site = Site(resource)

    if SSL == "ssl":
        certData = getModule(__name__).filePath.sibling('server.pem').getContent()
        certificate = ssl.PrivateCertificate.loadPEM(certData)
        reactor.listenSSL(int(PORT), site, certificate.options())
        proto = "https"
    else:
        reactor.listenTCP(int(PORT), site, interface=HOST)
        proto = "http"

    logging.info("listening on: %s:%d" % (HOST, int(PORT)))
    logging.info('wsdl is at: %s://%s:%d/?wsdl' % (proto, HOST, int(PORT)))

    sys.exit(reactor.run())
