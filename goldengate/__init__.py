from goldengate.rules import find_rule

from webob import Request, Response
from webob.exc import HTTPNotFound
import yaml

from traceback import format_exc
from urlparse import urlparse
import httplib
import os.path
import sys
import os


class RuleEngine(object):
    """Compiles and processes goldengate rulesets"""
    def __init__(self, ruletype, ruleset):
        """Initialize the RuleEngine

        Arguments:
        ruletype -- type of rules to process (match, filter, modify_request,
                    modify_response, audit_request, audit_response)
        ruleset -- list of rule strings (eg. ['reject all status=403'])

        """
        self.ruletype = ruletype
        self.ruleset = ruleset

        if not self.ruleset:
            self.ruleset = []

        self.compiled = []
        self.compile()

    def __repr__(self):
        return 'RuleEngine(%r, %r)' % (self.ruletype, self.ruleset)

    def compile(self):
        """Compile the ruleset into a list of function references and args"""
        for rule in self.ruleset:
            rule = rule.replace('\ ', '\x00')
            rule = rule.split(' ')
            rule = [x.replace('\x00', ' ') for x in rule]

            args = [x for x in rule if x.find('=') == -1]
            kwargs = dict([x.split('=', 1) for x in rule if x.find('=') != -1])

            if self.ruletype == 'filter':
                verb = rule[1]
                args = args[1:]
            else:
                verb = rule[0]

            self.compiled.append(
                (find_rule(self.ruletype, verb)(*args, **kwargs), rule))

    def test_match(self, request):
        """Test match rules

        Arguments:
        request -- A webob request object

        Returns:
        True if this ruleset matches, False otherwise
        """
        for rule, text in self.compiled:
            result = rule(request)
            if not result:
                return False
        return True

    def test_filter(self, request):
        """Test filter rules

        Arguments:
        request -- A webob request object

        Returns:
        True if the request should be permitted, False otherwise
        """
        for rule, text in self.compiled:
            result = rule(request)
            if text[0] == 'reject':
                return not result
            if text[0] == 'permit':
                return result

    def modify_request(self, request):
        """Modify the request

        Arguments:
        request -- A webob request object

        Returns:
        A webob request object that has been modified in accordance with this
        ruleset
        """
        for rule, text in self.compiled:
            request = rule(request)
        return request

    def modify_response(self, response):
        """Modify the response

        Arguments:
        response -- A webob response object

        Returns:
        A response object modified in accordance with this ruleset
        """
        for rule, text in self.compiled:
            response = rule(response)
        return response

    def audit_request(self, request):
        """Audit the request

        Arguments:
        request -- A webob request object
        """
        for rule, text in self.compiled:
            rule(request)
        return request

    def audit_response(self, response):
        """Audit the response

        Arguments:
        response -- A webob response object
        """
        for rule, text in self.compiled:
            rule(response)
        return response


class Application(object):
    """goldengate WSGI application

    Arguments:
    configfile -- Path to a file containing a valid YAML ruleset. If not
                  specified, the config will be loaded from the first of these
                  files that can be read:
                    ./goldengate.conf
                    ~/.goldengate/goldengate.conf
                    /etc/goldengate/goldengate.conf
    """
    def __init__(self, configfile=None):
        if not configfile:
            for filename in (
                os.environ.get('GOLDENGATE_CONFIG', None),
                os.environ['PWD'] + '/goldengate.conf',
                os.environ['HOME'] + '/.goldengate/goldengate.conf',
                '/etc/goldengate/goldengate.conf'):
                if filename and os.access(filename, os.R_OK):
                    configfile = filename
                    break
        if not configfile:
            raise Exception('Unable to find goldengate.conf, giving up.')

        self.load_config(os.path.abspath(configfile))

    def load_config(self, filename):
        """Load a config file into this instance's self.config variable

        Arguments:
        filename -- Path to a file containing a valid YAML ruleset
        """
        self.config = yaml.load_all(open(filename, 'r'))
        self.config = list(self.config)

        self.rules = []
        for ruleset in self.config:
            engines = {}
            for section in ruleset:
                engines[section] = RuleEngine(section, ruleset[section])
            self.rules.append(engines)

    def proxy_request(self, request):
        """Proxy the given request to an upstream server, based on the
        request.goldengate_url or request.url attribute.

        Arguments:
        request -- A webob request object

        Returns:
        A webob response object
        """
        if not request.headers['Content-Type']:
            del request.headers['Content-Type']
        request.headers['Content-Length'] = len(request.body)
        request.headers['Connection'] = 'close'
        adhoc = {
            'url': request.url,
            'method': request.method,
        }
        for key, value in request.environ['webob.adhoc_attrs'].items():
            if not key.startswith('goldengate_'):
                continue
            key = key.split('_', 1)[1]
            adhoc[key] = value

        p = urlparse(adhoc['url'])
        if p.scheme == 'http':
            conn = httplib.HTTPConnection(p.netloc)
        if p.scheme == 'https':
            conn = httplib.HTTPSConnection(p.netloc)

        conn.request(adhoc['method'], adhoc['url'], request.body,
                     request.headers)
        response = conn.getresponse()
        #return Response(status=response.status, headers=response.getheaders(),
        #                app_iter=response.fp.readlines())
        body = response.read()
        conn.close()
        return Response(status=response.status, headers=response.getheaders(),
                        body=body)

    def __call__(self, environ, start_response):
        """WSGI application

        Arguments:
        environ -- WSGI environment dict
        start_response -- Reference to a function complying with PEP 333

        Returns:
        An iterable object yielding strings.
        """

        print repr(environ)
        request = Request(environ)
        response = None

        for ruleset in self.rules:
            try:
                print 'params', repr(request.params)
                print 'headers', repr(request.headers)
                print 'path', repr(request.path)
                if not ruleset['match'].test_match(request):
                    continue

                if not ruleset['filter'].test_filter(request):
                    response = Response(status=403, body='Verboten\n')
                else:
                    request = ruleset['modify_request'].modify_request(request)
                    response = self.proxy_request(request)
                    response = \
                        ruleset['modify_response'].modify_response(response)
            except Exception:
                print format_exc()
                response = Response(status=500, body='Internal Server Error')
            break

        if not response:
            response = Response(status=501, body='This shouldn\'t happen.\n')

        return response(environ, start_response)

application = Application()
