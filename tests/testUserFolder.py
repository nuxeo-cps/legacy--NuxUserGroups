#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

import base64
from Testing import ZopeTestCase
from Testing.ZopeTestCase import _user_name, _user_role, _folder_name, \
    _standard_permissions, ZopeLite
from AccessControl import Unauthorized

from Products.NuxUserGroups.UserFolderWithGroups import \
    UserFolderWithGroups, addUserFolderWithGroups

_pm = 'ThePublishedMethod'

ZopeLite.installProduct('NuxUserGroups')
ZopeLite.installProduct('CPSDirectory')

class TestBase(ZopeTestCase.ZopeTestCase):

    _setup_fixture = 0

    def afterSetUp(self):
        self._setupFolder()
        self.folder.manage_addProduct['NuxUserGroups'].addUserFolderWithGroups()
        self.uf = self.folder.acl_users
        self.uf.userFolderAddUser(_user_name, 'secret', (_user_role,), ())
        self._user = self.uf.getUserById(_user_name).__of__(self.uf)
        self._setPermissions(_standard_permissions)

    def beforeClose(self, call_close_hook=1):
        '''Clears out the fixture.'''
        self._logout()
        try: del self.uf
        except AttributeError: pass
        try: del self.folder.acl_users
        except AttributeError: pass
        try: self.app._delObject(_folder_name)
        except (AttributeError, RuntimeError): pass
        try: del self.folder
        except AttributeError: pass
        try: del self._user
        except AttributeError: pass

    def _setupPublishedMethod(self):
        self.folder.addDTMLMethod(_pm, file='some content')
        pm = self.folder[_pm]
        for p in _standard_permissions:
            pm.manage_permission(p, [_user_role], acquire=0)

    def _setupPublishedRequest(self):
        request = self.app.REQUEST
        request.set('PUBLISHED', self.folder[_pm])
        request.set('PARENTS', [self.folder, self.app])
        request.steps = [_folder_name, _pm]

    def _basicAuth(self, name):
        return 'Basic %s' % base64.encodestring('%s:%s' %(name, 'secret'))

    def _call__roles__(self, object):
        # From BaseRequest.traverse()
        roles = ()
        object = getattr(object, 'aq_base', object)
        if hasattr(object, '__call__') \
          and hasattr(object.__call__, '__roles__'):
            roles = object.__call__.__roles__
        return roles


class TestUserFolder(TestBase):
    '''Test UF is working'''

    def testGetUser(self):
        assert self.uf.getUser(_user_name) is not None

    def testGetUsers(self):
        users = self.uf.getUsers()
        assert users != []
        assert users[0].getUserName() == _user_name

    def testGetUserNames(self):
        names = self.uf.getUserNames()
        assert names != []
        assert names[0] == _user_name

    def testIdentify(self):
        auth = self._basicAuth(_user_name)
        name, password = self.uf.identify(auth)
        assert name is not None
        assert name == _user_name
        assert password is not None

    def testGetRoles(self):
        user = self.uf.getUser(_user_name)
        assert _user_role in user.getRoles()

    def testGetRolesInContext(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        roles = user.getRolesInContext(self.folder)
        assert _user_role in roles
        assert 'Owner' in roles

    def testHasRole(self):
        user = self.uf.getUser(_user_name)
        assert user.has_role(_user_role, self.folder)

    def testHasLocalRole(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        assert user.has_role('Owner', self.folder)

    def testHasPermission(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_role(_user_role,
            _standard_permissions + ['Add Folders'])
        self.login()
        assert user.has_permission('Add Folders', self.folder)

    def testHasLocalPermission(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_role('Owner', ['Add Folders'])
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        self.login()
        assert user.has_permission('Add Folders', self.folder)

    def testAuthenticate(self):
        user = self.uf.getUser(_user_name)
        assert user.authenticate('secret', self.app.REQUEST)

class TestAccess(TestBase):
    '''Test UF is protecting access'''

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        self._setupPublishedMethod()

    def testAllowAccess(self):
        self.login()
        try:
            self.folder.restrictedTraverse(_pm)
        except Unauthorized:
            self.fail('Unauthorized')

    def testDenyAccess(self):
        self.assertRaises(Unauthorized, self.folder.restrictedTraverse, _pm)


class TestValidate(TestBase):
    '''Test UF is authorizing us'''

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        self._setupPublishedMethod()
        self._setupPublishedRequest()

    def testAuthorize(self):
        # Validate should log us in
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        user = self.uf.validate(request, auth, [_user_role])
        assert user is not None
        assert user.getUserName() == _user_name

    def testNotAuthorize(self):
        # Validate should fail without auth
        request = self.app.REQUEST
        auth = ''
        assert self.uf.validate(request, auth, [_user_role]) is None

    # This fails with all user folders.
    # I'm not convinced Validate SHOULD fail without roles
    # If it should, then BasicUserFolder has it wrong.
    # def testNotAuthorize2(self):
    #     # Validate should fail without roles
    #     request = self.app.REQUEST
    #     auth = self._basicAuth(_user_name)
    #     self.assertEqual(self.uf.validate(request, auth),None)

    def testNotAuthorize3(self):
        # Validate should fail with wrong roles
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        assert self.uf.validate(request, auth, ['Manager']) is None

    def testAuthorize2(self):
        # Validate should allow us to call dm
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        roles = self._call__roles__(self.folder[_pm])
        user = self.uf.validate(request, auth, roles)
        assert user is not None
        assert user.getUserName() == _user_name

    def testNotAuthorize4(self):
        # Validate should deny us to call dm
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        pm = self.folder[_pm]
        for p in _standard_permissions:
            pm.manage_permission(p, [], acquire=0)
        roles = self._call__roles__(pm)
        assert self.uf.validate(request, auth, roles) is None


class TestCPSAPI(TestBase):

    def testCPSRoleAPI(self):
        _user_name2 = 'test_user_2_'
        _user_role2 = 'test_role_2_'
        self.uf.userFolderAddUser(_user_name2, 'pass', [], [])
        self.uf.userFolderAddRole(_user_role2)
        self.assert_(_user_role2 in self.folder.userdefined_roles())
        self.uf.setRolesOfUser((_user_role, _user_role2), _user_name)
        self.uf.setUsersOfRole((_user_name, _user_name2), _user_role)
        roles = list(self.uf.getUser(_user_name).getRoles())
        roles.sort()
        self.assert_(roles == ['Authenticated', _user_role, _user_role2])
        owners = self.uf.getUsersOfRole(_user_role)
        owners.sort()
        self.assert_(owners == [_user_name, _user_name2])
        self.assert_(self.uf.getUsersOfRole(_user_role2) == [_user_name])
        self.uf.userFolderDelRoles((_user_role2,))
        self.assert_(_user_role2 not in self.folder.userdefined_roles())


    def testCPSGroupAPI(self):
        _user_name2 = 'test_user_2_'
        _user_group = 'test_group_1_'
        _user_group2 = 'test_group_2_'
        self.uf.userFolderAddUser(_user_name2, 'pass', [], [])
        self.uf.userFolderAddGroup(_user_group)
        self.uf.userFolderAddGroup(_user_group2)
        self.assert_(self.uf.getGroupById(_user_group) is not None)
        groups = list(self.uf.getGroupNames())
        groups.sort()
        self.assert_(groups == [_user_group , _user_group2])
        self.uf.setGroupsOfUser([_user_group, _user_group2], _user_name)
        self.uf.setUsersOfGroup([_user_name2, _user_name], _user_group)
        users = list(self.uf.getGroupById(_user_group).getUsers())
        users.sort()
        self.assert_(users == [_user_name, _user_name2])
        groups = list(self.uf.getUser(_user_name).getGroups())
        groups.sort()
        self.assert_(groups == [_user_group, _user_group2])

if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestUserFolder))
        suite.addTest(unittest.makeSuite(TestAccess))
        suite.addTest(unittest.makeSuite(TestValidate))
        suite.addTest(unittest.makeSuite(TestCPSAPI))
        return suite

