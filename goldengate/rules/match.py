from goldengate.rules.base import MatchRule, RuleException
from goldengate.rules import add_rule

from IPy import IP
import re


class AllMatchRule(MatchRule):
    """Matches all requests, unconditionally"""
    verbs = ['all']

    def __call__(self, request):
        return True


class NoneMatchRule(MatchRule):
    """Matches no requests, unconditionally"""
    verbs = ['none']

    def __call__(self, request):
        return False


class RequestMatchRule(MatchRule):
    """Matches requests based on one of several parameters"""
    verbs = ['method', 'scheme', 'script_name', 'path_info', 'remote_user',
             'remote_addr', 'host', 'host_url', 'application_url', 'path_url',
             'url', 'path', 'path_qs', 'query_string']

    def __init__(self, *args, **kwargs):
        if len(args) < 3:
            raise RuleException('RequestMatchRule requires at least a "verb"' \
                                ' "type" and "match"')
        self.verb = args[0]
        self.matchtype = args[1]
        self.params = args[2:]

        if not self.verb in self.verbs:
            raise RuleException('Unknown verb: %s' % self.verb)

        if not hasattr(self, 'match_' + self.matchtype):
            raise RuleException('Unknown match type: %s' % self.matchtype)
        else:
            self.matchfunc = getattr(self, 'match_' + self.matchtype)

    def __call__(self, request):
        value = getattr(request, self.verb)
        return self.matchfunc(value)

    def match_regex(self, value):
        for pattern in self.params:
            match = re.match(self.params[0], value)
            if match:
                return True
        return False

    def match_subnet(self, value):
        value = IP(value)
        for subnet in self.params:
            if value in IP(subnet):
                return True
        return False

    def match_is(self, value):
        return value == self.params[0]

    def match_in(self, value):
        return value in self.params


class HeaderMatchRule(RequestMatchRule):
    """Matches requests with the given headers"""
    verbs = ['header']

    def __init__(self, *args, **kwargs):
        if len(args) < 3:
            raise RuleException('HeaderMatchRule requires at least a ' \
                                '"key", "type", and "value"')
        self.verb = args[0]
        self.key = args[1]
        self.matchtype = args[2]
        self.params = args[3:]

        if not self.verb in self.verbs:
            raise RuleException('Unknown verb: %s' % self.verb)

        if not hasattr(self, 'match_' + self.matchtype):
            raise RuleException('Unknown match type: %s' % self.matchtype)
        else:
            self.matchfunc = getattr(self, 'match_' + self.matchtype)

    def __call__(self, request):
        value = request.headers.get(self.key, None)
        if not value:
            return False
        return self.matchfunc(value)

add_rule(AllMatchRule)
add_rule(NoneMatchRule)
add_rule(RequestMatchRule)
add_rule(HeaderMatchRule)
