import time
import uuid
from . import settings
from .notifications import Notification
from .sausagefactory import AuditTrail
try:
    import simplejson as json
except ImportError:
    import json
from kvstore import models


def action(action, allow, entities=None, **kwargs):
    """
    Helper for constructing AWS policies. The policy will match AWS request that
    match a particular action. If allow is True the request will be granted. If
    it's False it will be denied. Otherwise, allow is assumed to be a callable
    that will return a Policy object.

    """
    matcher = AWSActionMatcher(action)
    if entities is not None:
        matcher = AllMatcher([EntityMatcher(entities), matcher])

    if allow is True:
        return AllowPolicy(matcher, **kwargs)
    elif allow is False:
        return DenyPolicy(matcher, **kwargs)
    else:
        return allow(matcher, **kwargs)


def allow():
    "Helper for constructing a default-allow policy."
    return AllowPolicy(AlwaysMatcher())


def deny():
    "Helper for constructing a default-deny policy."
    return DenyPolicy(AlwaysMatcher())


def render_template(template, context):
    """
    Replaces {{ <var> }} with the value of the variable from the context
    dictionary.
    """
    for key, value in context.iteritems():
        template = template.replace('{{ %s }}' % (key,), value)
    return template


class MissingPolicyException(Exception):
    pass


class Policy(object):
    def applies_to(self, entity, request):
        """Returns true if this policy applies to the request."""
        raise NotImplementedError()

    def grant(self, entity, request):
        """Should we grant entity permission to perform request?"""
        raise NotImplementedError()

    @classmethod
    def for_request(self, entity, request, policies=None):
        policies = policies if policies is not None else settings.policies
        for policy in policies:
            if policy.applies_to(entity, request):
                return policy
        raise MissingPolicyException


class MatcherPolicy(object):
    def __init__(self, matcher):
        self.matcher = matcher

    def applies_to(self, entity, request):
        return self.matcher.matches(entity, request)


class BooleanPolicy(MatcherPolicy):
    def __init__(self, allow, matcher):
        self.allow = allow
        super(BooleanPolicy, self).__init__(matcher)

    def grant(self, entity, request):
        return self.allow


class AllowPolicy(BooleanPolicy):
    def __init__(self, matcher):
        super(AllowPolicy, self).__init__(True, matcher)


class DenyPolicy(BooleanPolicy):
    def __init__(self, matcher):
        super(DenyPolicy, self).__init__(False, matcher)


class TimeLock(models.Model):
    id = models.Field(pk=True)
    cancelled = models.Field(default=False)


class TimeLockPolicy(MatcherPolicy):
    """
    A time-lock policy queues requests for execution after some time has
    elapsed. During the time-lock phase of the request a notification will be
    sent to other parties who may be interested in the request. Those parties
    may decide to cancel the request at any period during the time-lock. If the
    request is not cancelled, it will be granted after the lock expires.

    """

    def __init__(self, matcher, lock_duration, notification_broker, notification_template, notification_recipients):
        self.lock_duration = lock_duration
        self.notification_broker = notification_broker
        self.notification_template = notification_template
        self.notification_recipients = notification_recipients
        super(TimeLockPolicy, self).__init__(matcher)

    @classmethod
    def cancel(cls, request_uuid):
        print 'Canceling request', request_uuid
        request = TimeLock.get(request_uuid)
        if request is None:
            raise Exception("Couldn't find request with uuid '%s'" % (request_uuid,))
        request.cancelled = True
        request.save()

    def grant(self, entity, request):
        # Generate UUID, add to list of pending requests, send email with
        # link for cancellation.
        request_uuid = uuid.uuid4().get_hex()
        timelock = TimeLock(id=request_uuid, cancelled=False)
        timelock.save()
        message = render_template(self.notification_template, {
            'request_information': AuditTrail.sanitize(json.dumps(request.to_dict(), indent=4)),
            'request_execution_time': time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(time.time() + self.lock_duration)),
            'time_lock_duration': str(self.lock_duration/60.0),
            'request_uuid': request_uuid,
        })
        self.notification_broker.send(Notification(self.notification_recipients, message))
        time.sleep(self.lock_duration)
        return not TimeLock.get(request_uuid).cancelled


class Matcher(object):
    def matches(self, entity, request):
        raise NotImplementedError()


class AllMatcher(Matcher):
    def __init__(self, matchers):
        self.matchers = matchers

    def matches(self, entity, request):
        for matcher in self.matchers:
            if not matcher.matches(entity, request):
                return False
        return True


class AnyMatcher(Matcher):
    def __init__(self, matchers):
        self.matchers = matchers

    def matches(self, entity, request):
        for matcher in self.matchers:
            if matcher.matches(entity, request):
                return True
        return False


class NotMatcher(Matcher):
    def __init__(self, matcher):
        self.matcher = matcher

    def matches(self, entity, request):
        return not self.matcher.matches(entity, request)


class EntityMatcher(Matcher):
    def __init__(self, entities):
        self.entities = entities

    def matches(self, entity, request):
        return entity in self.entities


class AWSActionMatcher(Matcher):
    def __init__(self, action):
        self.action = action

    def matches(self, entity, request):
        action = getattr(request, 'aws_action', None)
        if action is None:
            return False
        else:
            return action == self.action


class AlwaysMatcher(Matcher):
    def matches(self, entity, request):
        return True
