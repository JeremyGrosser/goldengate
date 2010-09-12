class RuleException(Exception):
    """Raised whenever a goldengate rule cannot be compiled or executed"""
    pass


class Rule(object):
    """Base class for all Rules"""
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __call__(self, request):
        raise NotImplementedError


class FilterRule(Rule):
    """Base class for all filter rules"""
    ruletype = 'filter'


class MatchRule(Rule):
    """Base class for all match rules"""
    ruletype = 'match'


class ModifyRule(Rule):
    """Base class for all modify rules"""
    ruletype = 'modify'
