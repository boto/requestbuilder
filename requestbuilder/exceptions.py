# Copyright (c) 2012-2013, Eucalyptus Systems, Inc.
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


class ArgumentError(ValueError):
    '''
    A bad command line argument should cause the command to fail
    '''
    pass


class ClientError(Exception):
    '''
    General client error (e.g. error accessing the server)
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


class ServerError(Exception):
    '''
    An error response from the server
    '''

    def __init__(self, response, *args):
        Exception.__init__(self, response.status_code, response.reason, *args)
        self.response = response

    @property
    def body(self):
        return self.response.text

    @property
    def reason(self):
        return self.response.reason

    @property
    def status_code(self):
        return self.response.status_code

    def format_for_cli(self):
        return 'error ({0}): {1}'.format(self.status_code,
                                         self.body or self.reason)
