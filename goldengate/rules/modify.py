from goldengate.rules.base import ModifyRule, RuleException
from goldengate.rules import add_rule

import re


class URLModifyRule(ModifyRule):
    """Modify the url or method of a request"""
    verbs = ['url', 'method']

    def __init__(self, *args, **kwargs):
        if len(args) < 2:
            raise RuleException('URLModifyRule requires "verb" and "action"')

        self.verb = args[0]
        self.action = args[1]
        if len(args) >= 3:
            self.value = args[2]
        else:
            self.value = None

        if self.action != 'set':
            raise RuleException('Request verbs can only be "set", not "%s"' %
                                self.action)

    def __call__(self, request):
        request.__setattr__('goldengate_' + self.verb, self.value)
        return request


class RequestModifyRule(ModifyRule):
    """Modify an attribute of the request"""
    verbs = ['content_type', 'charset', 'host', 'body', 'cache_control']

    def __init__(self, *args, **kwargs):
        if len(args) < 2:
            raise RuleException('RequestModifyRule requires "verb" and ' \
                                '"action"')

        self.verb = args[0]
        self.action = args[1]
        self.value = ' '.join(args[2:])

        if self.action != 'set':
            raise RuleException('Request verbs can only be "set", not "%s"' %
                                self.action)

    def __call__(self, request):
        request.__setattr__(self.verb, self.value)
        return request


class HeaderModifyRule(ModifyRule):
    """Modify the headers of a rule"""
    verbs = ['header']

    def __init__(self, *args, **kwargs):
        if len(args) < 3:
            raise RuleException('HeaderModifyRule requires "action" and "key"')

        self.verb = args[0]
        self.action = args[1]
        self.key = args[2]
        self.value = ' '.join(args[3:])

        if not hasattr(self, 'header_' + self.action):
            raise RuleException('Unknown header action: %s' % self.action)
        self.applyfunc = getattr(self, 'header_' + self.action)

    def template_value(self, request):
        '''
        Crazy regex magic to replace things like $remote_user with a real
        value. This is moderately dangerous if a malicious user controls your
        config.
        '''
        value = self.value
        for match in re.finditer('\$([a-z_]+)', self.value):
            key = match.group(0)
            replace = getattr(request, key, None)
            if replace == None:
                replace = request.environ.get(key, None)
            if replace == None:
                raise RuleException('Unable to replace template variable %s:' \
                                    ' unknown request attribute.' % key)
            start, end = match.span(0)
            value = value[:start - 1] + replace + value[end:]
        return value

    def __call__(self, request):
        value = self.template_value(request)
        return self.applyfunc(request, value)

    def header_set(self, request, value):
        request.headers[self.key] = value
        return request

    def header_remove(self, request, value=None):
        del request.headers[self.key]
        return request

add_rule(HeaderModifyRule)
add_rule(URLModifyRule)
add_rule(RequestModifyRule)
