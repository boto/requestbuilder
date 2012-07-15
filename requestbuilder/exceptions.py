# Copyright (c) 2012, Eucalyptus Systems, Inc.
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    from xml.etree import ElementTree
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

class ClientError(Exception):
    '''
    General client error (error accessing the server)
    '''
    pass


class AuthError(ClientError):
    '''
    Authentication handler failure
    '''
    pass


class ServiceInitError(ClientError):
    '''
    Failure to set up a service
    '''

    def __init__(self, reason=None):
        ClientError.__init__(self, reason)


class ServerError(RuntimeError):
    '''
    An error response from the server
    '''

    def __init__(self, status, body=None, *args):
        RuntimeError.__init__(self, *args)
        self.status_code = status  # HTTP status code
        self.body        = body or ''
        self.code        = None    # API error code
        self.message     = None    # Error message

        if self.body:
            try:
                xml_stream = StringIO.StringIO(self.body)
                for event, elem in ElementTree.iterparse(xml_stream,
                                                         events=('end',)):
                    if elem.tag == 'Code':
                        self.code = elem.text
                    elif elem.tag == 'Message':
                        self.message = elem.text
            except ElementTree.ParseError as err:
                # Dump the unparseable message body so we don't include
                # unusable garbage in the exception.  Since Eucalyptus
                # frequently returns plain text and/or broken XML, store it
                # in case we need it later.
                self.message = self.body
                self.body    = None

    def __str__(self):
        return '{cls}: {status} {reason}'.format(self.__class__.__name__,
                                                 self.status, self.reason)
