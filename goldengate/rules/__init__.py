all_rules = {}


def add_rule(rule):
    """Add a rule class to the global list of rule types"""
    global all_rules

    if not rule.ruletype in all_rules:
        all_rules[rule.ruletype] = {}

    for verb in rule.verbs:
        all_rules[rule.ruletype][verb] = rule


def find_rule(ruletype, verb):
    """Returns a rule of the given type that implements the given verb"""
    if ruletype.startswith('modify_'):
        ruletype = 'modify'
    if ruletype.startswith('audit_'):
        ruletype = 'audit'
    return all_rules[ruletype][verb]


from base import *
import match
import filter
import modify
import aws
