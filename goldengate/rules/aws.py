from goldengate.rules.base import FilterRule, ModifyRule, RuleException
from goldengate.rules import add_rule

import yaml

from urlparse import parse_qsl
import calendar
import base64
import urllib
import hmac
import time
import sys

TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


def generate_timestamp():
    """Generate a timestamp in the proper format for signing AWS requests"""
    return time.strftime(TIME_FORMAT, time.gmtime())


def parse_timestamp(timestamp):
    """Parse a timestamp from an AWS request

    Arguments:
    timestamp -- A string in the form %Y-%m-%dT%H:%M:%S

    Returns:
    An integer number of seconds since the unix epoch
    """
    return calendar.timegm(time.strptime(timestamp, TIME_FORMAT))


def escape(s):
    """Escape a string according to Amazon's quoting rules"""
    return urllib.quote(s, safe='-_~')


def encode_request(request):
    """Encode a request into a mutable dict object

    Arguments:
    request -- A webob request object

    Returns:
    A mutable dict containing most of the components required to generate an
    AWS signature
    """
    return {
        'params': request.params,
        'method': request.method,
        'headers': request.headers,
        'path': request.path,
    }


class SignatureMethod(object):
    """Base class for all AWS signature methods"""

    @property
    def name(self):
        raise NotImplementedError

    def build_signature(self, request, aws_secret):
        raise NotImplementedError

    def build_signature_base_string(self, request):
        """Returns a base string suitable for signing AWS requests

        Arguments:
        request -- A dict containing 'method', 'headers', 'path', and 'params'

        Returns:
        A string formatted for request signing
        """
        params = request['params'].items()
        params.sort()
        params = '&'.join(['%s=%s' % (escape(k), escape(v)) \
                           for k, v in params if k != 'Signature'])
        return params, '\n'.join((
            request['method'],
            request['headers']['Host'].lower(),
            request['path'] or '/',
            params,
        ))


class SignatureMethod_HMAC_SHA1(SignatureMethod):
    name = 'HmacSHA1'
    version = '2'

    def build_signature(self, request, aws_secret):
        """Sign the given request with the given secret using HMAC-SHA1

        Arguments:
        request -- A dict containing 'method', 'headers', 'path', and 'params'
        aws_secret -- A string value to be used as the signing secret. The
                      secret should correspond to the AWSAccessKeyId in the
                      request parameters.

        Returns:
        A base64 encoded request signature
        """
        params, base = self.build_signature_base_string(request)
        try:
            import hashlib  # 2.5
            hashed = hmac.new(aws_secret, base, hashlib.sha1)
        except ImportError:
            import sha  # deprecated
            hashed = hmac.new(aws_secret, base, sha)
        return params, base64.b64encode(hashed.digest())


class SignatureMethod_HMAC_SHA256(SignatureMethod):
    name = 'HmacSHA256'
    version = '2'

    def build_signature(self, request, aws_secret):
        """Sign the given request with the given secret using HMAC-SHA256

        Arguments:
        request -- A dict containing 'method', 'headers', 'path', and 'params'
        aws_secret -- A string value to be used as the signing secret. The
                      secret should correspond to the AWSAccessKeyId in the
                      request parameters.

        Returns:
        A base64 encoded request signature
        """
        import hashlib
        params, base = self.build_signature_base_string(request)
        hashed = hmac.new(aws_secret, base, hashlib.sha256)
        return params, base64.b64encode(hashed.digest())


class AWSSignatureFilterRule(FilterRule):
    """Filter for AWS request signatures

    This filter will only pass if the given request has a valid signature based
    on a key and secret present in the file specified by the "creds" argument.

    Example rule:
    permit aws_signature creds=aws.creds max_signature_age=300

    Example credentials file:
    ---
    name: example@example.com
    key: Nj4jT6JyEgMtDUgU
    secret: yPhnQEuB9CkksqXb6RaggqTkNEBEdpJC
    ---
    name: example2@example.com
    key: us6LJYaJqag67C9G
    secret: ph99WLvGy9jPvvWW6L3ELncfXCNzQlHr
    """
    verbs = ['aws_signature']

    signature_methods = [
        SignatureMethod_HMAC_SHA1,
        SignatureMethod_HMAC_SHA256,
    ]

    def __init__(self, verb, creds, max_signature_age=300):
        """Initialize the filter rule

        Arguments:
        verb -- The name used to lookup this rule (should always be
                aws_signature)
        creds -- Path to a file containing AWS credentials to be considered
                 valid
        max_signature_age -- The maximum number of seconds to allow the
                             request Timestamp to be offset by
        """
        self.verb = verb
        self.max_signature_age = int(max_signature_age)

        filename = creds
        try:
            self.creds = list(yaml.load_all(open(filename, 'r')))
        except:
            raise RuleException('Unable to load AWS credentials from %s: ' \
                                '%s' % (filename, sys.exc_info()[1]))

    @classmethod
    def get_signature_method(cls, name, version):
        """Returns a SignatureMethod instance for the given algorithm"""
        for method in cls.signature_methods:
            if method.name == name and method.version == version:
                return method()
        raise RuleException('Invalid signature method or version: method=%s ' \
                            'version=%s' % (name, version))

    def validate_timestamp(self, request):
        """Check the validity of the timestamp in the given request"""
        now = time.time()

        ts = parse_timestamp(request.params['Timestamp'])
        if 'Expires' in request.params:
            expires = parse_timestamp(request.params['Expires'])
            if expires < now:
                raise RuleException('Request Expires time is in the past: ' \
                                    '%s' % expires)

        if ts > now:
            raise RuleException('Timestamp may not be in the future')
        if self.max_signature_age and ts < (now - self.max_signature_age):
            raise RuleException('Timestamp may not be more than %s' \
                                           ' seconds ago')
        return True

    def validate_signature(self, request, aws_secret):
        """Re-creates the request signature using the given secret, then
        compares it against the original request.
        """
        signer = AWSSignatureFilterRule.get_signature_method(
            request.params['SignatureMethod'],
            request.params['SignatureVersion'])
        params, expected = signer.build_signature(
                                encode_request(request),
                                aws_secret)

        if request.params['Signature'] == expected:
            return True
        else:
            return False

    def get_credentials(self, request):
        """Returns the AWS secret from the credentials file that matches the
        access key in the request"""
        aws_key = request.params['AWSAccessKeyId']
        for cred in self.creds:
            if cred['key'] == aws_key:
                return (cred['key'], cred['secret'])
        raise RuleException('Access key not found in credentials file: %s' %
                            aws_key)

    def __call__(self, request):
        self.validate_timestamp(request)

        aws_key, aws_secret = self.get_credentials(request)
        return self.validate_signature(request, aws_secret)


class AWSSignModifyRule(ModifyRule):
    """Modifies the request by re-signing it with a different key and secret"""

    verbs = ['aws_sign']

    def __init__(self, verb, creds=None, key=None,
                 signature_method='HmacSHA256', signature_version='2'):
        """Initializes the modify rule

        Arguments:
        verb -- The name used to lookup this rule (should always be aws_sign)
        creds -- Path to a file containing the signing key and secret
        key -- Key to be used to re-sign the request
        signature_method -- Cryptographic signature method to sign the request
                            with (default: HmacSHA256)
        signature_version -- AWS signature version (default: 2)
        """
        self.signature_method = signature_method
        self.signature_version = signature_version
        self.verb = verb

        if not creds or not key:
            raise RuleException('Both "creds" and "key" are required ' \
                                'arguments for aws_sign')

        filename = creds
        try:
            creds = list(yaml.load_all(open(filename, 'r')))
        except:
            raise RuleException('Unable to load signing credentials from %s:' \
                                ' %s' % (filename, sys.exc_info()[1]))
        creds = [x for x in creds if x['key'] == key]
        if not creds:
            raise RuleException('Key %s is missing from %s' % (key, filename))
        creds = creds[0]

        self.key = creds['key']
        self.secret = creds['secret']

        self.signer = AWSSignatureFilterRule.get_signature_method(
                      signature_method, signature_version)

    # I hate this method and the implication that requests are read-only
    def __call__(self, request):
        if hasattr(request, 'goldengate_url'):
            url = request.goldengate_url
        else:
            url = request.url
        url, query = url.split('?', 1)
        #q = dict(parse_qsl(query))

        if 'Authorization' in request.headers:
            del request.headers['Authorization']

        params = dict(request.params)
        params.update({
            'AWSAccessKeyId': self.key,
            'SignatureVersion': self.signature_version,
            'SignatureMethod': self.signature_method,
            'Timestamp': generate_timestamp(),
        })

        r = {
            'params': params,
            'method': request.method,
            'path': request.path,
            'headers': request.headers,
        }

        params, signature = self.signer.build_signature(r, self.secret)

        #request.headers['Authorization'] = 'AWS %s:%s' % (self.key, signature)
        #del request.headers['Authorization']

        signature = urllib.quote_plus(signature)

        if request.content_type == 'application/x-www-form-urlencoded':
            request.body = '%s&Signature=%s' % (params, signature)
        else:
            request.goldengate_url = '%s?%s&Signature=%s' % (
                                        url, params, signature)
        return request

add_rule(AWSSignatureFilterRule)
add_rule(AWSSignModifyRule)
