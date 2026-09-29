import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/backend')
import database, auth_config, main
print('Backend imports OK')
print('Initial user:', auth_config.INITIAL_USERNAME)
print('Force change:', auth_config.FORCE_CHANGE)
