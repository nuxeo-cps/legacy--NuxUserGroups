#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from Testing.ZopeTestCase import _user_name, ZopeLite, ZopeTestCase
from AccessControl import Unauthorized
from Products.NuxUserGroups.UserFolderWithGroups import Group


class TestGroup(ZopeTestCase):
    # These tests are mostly here to prove that the full API is supported.
    # Most of the methods are trivial and need no testing per se.
    def testGetMembers(self):
        group = Group('groupa', ('user1', 'user2',))
        self.assertEqual(group.getUsers(), ('user1', 'user2',))

    
if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestGroup))
        return suite

