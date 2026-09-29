import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend'))
import database, auth_config
print('Imports OK')
print('Initial user:', auth_config.INITIAL_USERNAME)
print('Force change:', auth_config.FORCE_CHANGE)
print('Hash length:', len(auth_config.INITIAL_HASH))
