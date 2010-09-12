from goldengate.rules.base import FilterRule, RuleException
from goldengate.rules.match import AllMatchRule, NoneMatchRule, RequestMatchRule, HeaderMatchRule
from goldengate.rules import add_rule

import time


class AllFilterRule(AllMatchRule):
    """Filters all requests, unconditionally"""
    ruletype = 'filter'


class NoneFilterRule(NoneMatchRule):
    """Filters no requests, unconditionally"""
    ruletype = 'filter'


class RequestFilterRule(RequestMatchRule):
    """Filters requests based on one of several parameters"""
    ruletype = 'filter'


class HeaderFilterRule(HeaderMatchRule):
    """Filters requests based on headers"""
    ruletype = 'filter'

add_rule(AllFilterRule)
add_rule(NoneFilterRule)
add_rule(RequestFilterRule)
add_rule(HeaderFilterRule)
