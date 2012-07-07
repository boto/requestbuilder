import base64
import hashlib
import hmac
import requests.auth
from six import text_type
import time
import urllib
import urlparse
from .exceptions import AuthError

ISO8601 = '%Y-%m-%dT%H:%M:%SZ'

class QuerySignatureV2Auth(requests.auth.AuthBase):
    def __init__(self, service, key_id, key):
        self.service = service
        if not key_id:
            raise AuthError('missing key ID')
        if not key:
            raise AuthError('missing key')
        self.key_id = key_id
        self.hmac   = hmac.new(key, digestmod=hashlib.sha256)
        self.log    = self.service.log.getChild(self.__class__.__name__)

    def __call__(self, req):
        # We assume that req.params is a dict
        req.params['AWSAccessKeyId']   = self.key_id
        req.params['SignatureVersion'] = 2
        req.params['SignatureMethod']  = 'HmacSHA256'
        req.params['Timestamp']        = time.strftime(ISO8601, time.gmtime())
        if 'Signature' in req.params:
            # Needed for retries so old signatures aren't included in to_sign
            del req.params['Signature']
        parsed = urlparse.urlparse(req.url)
        to_sign = '{method}\n{host}\n{path}\n'.format(method=req.method,
                host=parsed.netloc.lower(), path=parsed.path)
        quoted_params = []
        for key in sorted(req.params):
            val = text_type(req.params[key])
            quoted_params.append(urllib.quote(key, safe='') + '=' +
                                 urllib.quote(val, safe='-_~'))
        query_string = '&'.join(quoted_params)
        to_sign += query_string
        self.log.debug('string to sign: %s', repr(to_sign))
        signature = self.sign_string(to_sign)
        self.log.debug('b64-encoded signature: %s', signature)
        req.params['Signature'] = signature
        return req

    def sign_string(self, to_sign):
        hmac = self.hmac.copy()
        hmac.update(to_sign)
        return base64.b64encode(hmac.digest())
