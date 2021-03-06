import hmac
import base64
import time
import calendar
import random

from .. import settings, http
from . import base, UnauthenticatedException


def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)


TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'
def generate_timestamp():
    return time.strftime(TIME_FORMAT, time.gmtime())
def parse_timestamp(timestamp):
    return calendar.timegm(time.strptime(timestamp, TIME_FORMAT))


def _are_equal(this, that):
    # Because someone is going to complain about timing attacks.
    if len(this) != len(that):
        return False
    rot = random.randint(0, len(this)-1)
    return (this[:rot] + this[rot:]) == (that[:rot] + that[rot:])


class SignatureMethod(object):

    @property
    def name(self):
        raise NotImplementedError

    def build_signature_base_string(self, request):
        signature = '\n'.join((
            request.get_normalized_http_method(),
            request.get_normalized_http_host(),
            request.get_normalized_http_path(),
            request.get_normalized_parameters(),
        ))
        return signature

    def build_signature(self, request, aws_secret):
        raise NotImplementedError


class SignatureMethod_HMAC_SHA1(SignatureMethod):
    name = 'HmacSHA1'
    version = '2'

    def build_signature(self, request, aws_secret):
        base = self.build_signature_base_string(request)
        try:
            import hashlib # 2.5
            hashed = hmac.new(aws_secret, base, hashlib.sha1)
        except ImportError:
            import sha # deprecated
            hashed = hmac.new(aws_secret, base, sha)
        return base64.b64encode(hashed.digest())


class SignatureMethod_HMAC_SHA256(SignatureMethod):
    name = 'HmacSHA256'
    version = '2'

    def build_signature(self, request, aws_secret):
        import hashlib
        base = self.build_signature_base_string(request)
        hashed = hmac.new(aws_secret, base, hashlib.sha256)
        return base64.b64encode(hashed.digest())


class Request(http.Request):
    """
    A request that uses Amazon AWS's token-based signature authentication,
    mostly used by their various REST APIs.

    """

    @property
    def aws_action(self):
        return self.url.parameters['Action']

    def get_normalized_parameters(self):
        """
        Returns an ordered list of all of the parameters required in the
        signature.

        """
        return http.urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in
                            sorted(self.url.parameters.iteritems())
                            if k != 'Signature'])

    def get_normalized_http_method(self):
        return self.method

    def get_normalized_http_host(self):
        host = self.url.host.lower()
        scheme = self.url.scheme.lower()
        if scheme == 'http' and host.endswith(':80') or \
           scheme == 'https' and host.endswith(':443'):
            host = ''.join(host.split(':')[:-1])
        return host

    def get_normalized_http_path(self):
        # For an empty path use '/'
        return self.url.path if self.url.path else '/'

    def signed_request(self, signature_method, aws_key, aws_secret):
        parameters = self.url.parameters.copy()
        parameters['AWSAccessKeyId'] = aws_key
        parameters['SignatureVersion'] = signature_method.version
        parameters['SignatureMethod'] = signature_method.name
        parameters['Timestamp'] = generate_timestamp()
        prepared = self._clone(url=http.clone_url(self.url, parameters=parameters))

        parameters['Signature'] = signature_method.build_signature(prepared, aws_secret)
        return self._clone(url=http.clone_url(prepared.url, parameters=parameters))


class Authenticator(base.Authenticator):
    """
    GoldenGate Authenticator that authenticates requests using Amazon's
    token-based authentication. If a request is authentic, the authenticate
    method will return the entity that made the request. If the request is not
    authentic (signature mismatch, expired timestamp, missing signature
    parameters, etc.) an `UnauthenticatedException` will be raised.

    """

    TIMESTAMP_THRESHOLD = 300 # In seconds, five minutes.
    signature_methods = [SignatureMethod_HMAC_SHA1(), SignatureMethod_HMAC_SHA256()]

    def __init__(self, credentials):
        self.credentials = credentials

    def authenticate(self, request):
        # Returns the authentic identity of the requester.
        try:
            aws_key = request.url.parameters['AWSAccessKeyId']
            signature = request.url.parameters['Signature']
            signature_method = request.url.parameters['SignatureMethod']
            signature_version = request.url.parameters['SignatureVersion']
            timestamp = request.url.parameters['Timestamp'] # TODO: Support Expires instead of / in addition to Timestamp.
        except KeyError:
            raise UnauthenticatedException('missing required signature parameters.')

        try:
            timestamp = parse_timestamp(timestamp)
        except ValueError:
            raise UnauthenticatedException('bad timestamp')

        # Timestamp can't be in the future, and can't be older than TIMESTAMP_THRESHOLD.
        if (timestamp > time.time() or
            timestamp < (time.time() - self.TIMESTAMP_THRESHOLD)):
            raise UnauthenticatedException('bad timestamp')

        credentials = self.credentials.for_key(aws_key)
        if credentials is None:
            raise UnauthenticatedException('signature mismatch')
        signer = self.get_signature_method(signature_method, signature_version)

        expected_signature = signer.build_signature(request._clone(klass=Request), credentials.secret)
        if _are_equal(signature, expected_signature):
            return credentials.entity
        else:
            raise UnauthenticatedException('signature mismatch')

    @classmethod
    def get_signature_method(cls, name, version):
        for method in cls.signature_methods:
            if method.name == name and method.version == version:
                return method
        raise UnauthenticatedException('invalid signature method or signature version')


class Authorizer(base.Authorizer):
    """
    AWS Authorizer that re-signs a request with the real AWS credentials after
    verifying that it's authorized.

    """
    signature_method = SignatureMethod_HMAC_SHA256()

    def __init__(self, aws_key=None, aws_secret=None, *args, **kwargs):
        self.aws_key = aws_key if aws_key is not None else settings.aws_key
        self.aws_secret = aws_secret if aws_secret is not None else settings.aws_secret
        super(Authorizer, self).__init__(*args, **kwargs)

    def prepare(self, entity, request):
        # Re-sign the request with the real AWS credentials.
        request = super(Authorizer, self).prepare(entity, request)
        return request._clone(klass=Request).signed_request(
            self.signature_method,
            self.aws_key,
            self.aws_secret
        )

    def authorize(self, entity, request):
        # Make sure request is an aws.Request
        return super(Authorizer, self).authorize(entity, request._clone(klass=Request))
