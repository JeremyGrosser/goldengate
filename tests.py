from wsgiref.simple_server import make_server
from StringIO import StringIO
import unittest
import sys

import webob

import goldengate.rules.match
import goldengate.rules.filter

class WSGIInput(object):
    def __init__(self, *args, **kwargs):
        self._wrapped = StringIO(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


class GoldenGateRuleTest(unittest.TestCase):
    def setUp(self):
        self.request = webob.Request({
            'HTTP_ACCEPT': '*/*',
            'SERVER_PORT': '8000',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'SERVER_SOFTWARE': 'gunicorn/0.11.1.943668f-git',
            'SCRIPT_NAME': '',
            'REQUEST_METHOD': 'GET',
            'HTTP_HOST': 'goldengate.example.com',
            'PATH_INFO': '/foo/bar',
            'QUERY_STRING': '',
            'CONTENT_LENGTH': '',
            'HTTP_USER_AGENT': 'curl/7.19.7 (universal-apple-darwin10.0)' \
                               'libcurl/7.19.7 OpenSSL/0.9.8l zlib/1.2.3',
            'REMOTE_PORT': '58217',
            'RAW_URI': '/',
            'REMOTE_ADDR': '127.0.0.1',
            'wsgi.input': WSGIInput(),
            'wsgi.multithread': False,
            'wsgi.version': (1, 0),
            'wsgi.run_once': False,
            'wsgi.errors': sys.stderr,
            'wsgi.multiprocess': False,
            'wsgi.url_scheme': 'http',
            'SERVER_NAME': '127.0.0.1',
            'CONTENT_TYPE': ''})


class GoldenGateMatchRuleTest(GoldenGateRuleTest):
    def test_all_match(self):
        rule = goldengate.rules.match.AllMatchRule()
        self.assertTrue(rule(self.request))

    def test_none_match(self):
        rule = goldengate.rules.match.NoneMatchRule()
        self.assertFalse(rule(self.request))

    # RequestMatchRule
    def test_request_regex_match(self):
        rule = goldengate.rules.match.RequestMatchRule('path', 'regex',
                                                       '^/foo')
        self.assertTrue(rule(self.request))

    def test_request_is_match(self):
        rule = goldengate.rules.match.RequestMatchRule('method', 'is', 'GET')
        self.assertTrue(rule(self.request))

    def test_request_subnet_match(self):
        rule = goldengate.rules.match.RequestMatchRule('remote_addr', 'subnet',
                                                       '127.0.0.0/8')
        self.assertTrue(rule(self.request))

    def test_request_in_match(self):
        rule = goldengate.rules.match.RequestMatchRule('scheme', 'in', 'http',
                                                       'https')
        self.assertTrue(rule(self.request))

    # HeaderMatchRule
    def test_header_regex_match(self):
        rule = goldengate.rules.match.HeaderMatchRule('header', 'User-Agent',
                                                      'regex', '^curl')
        self.assertTrue(rule(self.request))

    def test_header_subnet_match(self):
        # TODO: Not sure how to write this test
        pass

    def test_header_is_match(self):
        rule = goldengate.rules.match.HeaderMatchRule('header', 'Host', 'is',
                                                      'goldengate.example.com')
        self.assertTrue(rule(self.request))

    def test_header_in_match(self):
        rule = goldengate.rules.match.HeaderMatchRule('header', 'Accept',
                                                      'in', '', '*/*')
        self.assertTrue(rule(self.request))


class GoldenGateModifyRuleTest(GoldenGateRuleTest):
    def test_url_rule(self):
        rule = goldengate.rules.modify.URLModifyRule('url', 'set',
                                                     'http://example.com/')
        request = rule(self.request)
        self.assertEqual(request.goldengate_url, 'http://example.com/')

    def test_request_rule(self):
        rule = goldengate.rules.modify.RequestModifyRule('content_type', 'set',
                                                         'text/plain')
        request = rule(self.request)
        self.assertEqual(request.content_type, 'text/plain')

    def test_header_set_rule(self):
        rule = goldengate.rules.modify.HeaderModifyRule('header', 'set',
                                                        'Host', 'example.com')
        request = rule(self.request)
        self.assertEqual(request.headers['Host'], 'example.com')

    def test_header_remove_rule(self):
        rule = goldengate.rules.modify.HeaderModifyRule('header', 'remove',
                                                        'User-agent')
        request = rule(self.request)
        self.assertFalse('User-agent' in request.headers)
