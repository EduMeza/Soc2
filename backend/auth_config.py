import hashlib

INITIAL_USERNAME = "5205342"
INITIAL_HASH = hashlib.sha256("changeme_initial_5205342".encode()).hexdigest()

FORCE_CHANGE = 1
