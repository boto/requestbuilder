# Copyright (c) 2012-2016 Hewlett Packard Enterprise Development LP
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

from __future__ import absolute_import

import logging
import warnings


class BaseAuth(object):
    '''
    Basis for all authentication

    This class does nothing on its own.  It is up to you to implement the
    necessary functions to effect an authentication scheme.
    '''
    ARGS = []

    def __init__(self, config, loglevel=None, **kwargs):
        self.args = kwargs
        self.config = config
        self.log = logging.getLogger(self.__class__.__name__)
        if loglevel is not None:
            self.log.level = loglevel

    def configure(self):
        # TODO:  rename this to setup
        pass

    def apply_to_request(self, request, service):
        pass

    def bind_to_service(self, service):
        def wrapped_apply_to_request(req):
            return self.apply_to_request(req, service) or req
        return wrapped_apply_to_request


# Compatibility with requestbuilder < 0.3
from .aws import HmacKeyAuth
from .aws import HmacV1Auth as S3RestAuth
from .aws import QueryHmacV2Auth as QuerySigV2Auth
