import random

RANDOM_TOKEN_STRING_LENGTH = 16
RANDOM_TOKEN_ALPHABET = 'abcdefghjklmnpqrstuvwxyz' \
                        'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'


def random_token(length=RANDOM_TOKEN_STRING_LENGTH,
                 alphabet=RANDOM_TOKEN_ALPHABET):
    """Generate a random string with the given length and alphabet."""
    return ''.join(random.choice(alphabet) for _ in xrange(length))


def generate_credentials():
    """Print a random set of AWS credentials to stdout"""
    print 'key:', random_token()
    print 'secret:', random_token(32)
