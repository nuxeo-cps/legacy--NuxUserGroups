# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# Copyright (c) 2002 Préfecture du Bas-Rhin, France
# See license info at the end of this file.
# $Id$

"""
  UserFolderWithGroups
  A User Folder with groups support.
"""

__version__ = '$Revision$'[11:-2]


# In some places where "group" should be used we actually
# say "usergroup" to prevent clashes with some existing
# UserFolders that use "group" for "role".


import string, re, urllib, os

from Globals import InitializeClass, DTMLFile, MessageDialog, \
     Persistent, PersistentMapping
from Acquisition import aq_base, Implicit
from App.Management import Navigation, Tabs
from AccessControl import ClassSecurityInfo, getSecurityManager, Permissions
from AccessControl.Role import RoleManager
from AccessControl.User import User, UserFolder, _remote_user_mode, reqattr
from OFS.SimpleItem import Item

try:
    from AccessControl.User import DEFAULTMAXLISTUSERS
except:
    DEFAULTMAXLISTUSERS = 250


ManageUsers = Permissions.manage_users
_marker = []

class BasicGroup(Implicit, Persistent):
    """
    Base class for Group object
    """

    security = ClassSecurityInfo()

    # derived classes must call the base __init__
    def __init__(self, id, title='', **kw):
        self.id = id
        self.title = title

    #
    # To implement
    #

    security.declareProtected(ManageUsers, 'getUsers')
    def getUsers(self):
        """Group users"""
        return NotImplemented

    security.declarePrivate('_setUsers')
    def _setUsers(self, usernames):
        # this method is not responsible for keeping in sync
        # with the User objects or the GroupFolder
        return NotImplemented

    security.declarePrivate('_addUsers')
    def _addUsers(self, usernames):
        # this method is not responsible for keeping in sync
        # with the User objects or the GroupFolder
        return NotImplemented

    security.declarePrivate('_delUsers')
    def _delUsers(self, usernames):
        # this method is not responsible for keeping in sync
        # with the User objects or the GroupFolder
        return NotImplemented

    #
    # Basic API
    #

    security.declareProtected(ManageUsers, 'Title')
    def Title(self):
        """Group title"""
        return self.title

    security.declareProtected(ManageUsers, 'setTitle')
    def setTitle(self, title):
        self.title = title

    security.declareProtected(ManageUsers, 'edit')
    def edit(self, title=None, usernames=None, **kw):
        """edit the group"""
        if title is not None:
            self.setTitle(title)
        if usernames is not None:
            self.setUsers(usernames)


InitializeClass(BasicGroup)


class Group(BasicGroup):
    """
    Standard Group object
    """

    security = ClassSecurityInfo()

    def __init__(self, id, users=(), title=(), **kw):
        apply(BasicGroup.__init__, (self, id), kw)
        self.users = list(users)

    security.declareProtected(ManageUsers, 'getUsers')
    def getUsers(self):
        """Group users"""
        return tuple(self.users)

    security.declarePrivate('_setUsers')
    def _setUsers(self, usernames):
        self.users = list(usernames)

    security.declarePrivate('_addUsers')
    def _addUsers(self, usernames):
        users = self.users
        users.extend(usernames)
        self.users = users

    security.declarePrivate('_delUsers')
    def _delUsers(self, usernames):
        users = self.users
        for username in usernames:
            users.remove(username)
        self.users = users


InitializeClass(Group)



## class BasicGroupFolder(Implicit, Persistent, Navigation, Tabs,
##                        RoleManager, Item):
class BasicGroupFolderMixin:
    """
    Base class for GroupFolder-like objects.
    """

    security = ClassSecurityInfo()

    #
    # To implement
    #

    security.declareProtected(ManageUsers, 'userFolderAddGroup')
    def userFolderAddGroup(self, groupname, **kw):
        """Creates a group"""
        raise NotImplemented

    security.declareProtected(ManageUsers, 'userFolderDelGroups')
    def userFolderDelGroups(self, groupnames):
        """Deletes groups"""
        raise NotImplemented

    security.declareProtected(ManageUsers, 'getGroupNames')
    def getGroupNames(self):
        """Returns a list of group names"""
        raise NotImplemented

    security.declareProtected(ManageUsers, 'getGroupById')
    def getGroupById(self, groupname):
        """Returns the given group"""
        raise NotImplemented

    #
    # Basic API
    #

    # Maybe this should be put in the BasicUser class
    # however we'd need a way to call getGroupById() from there

    security.declareProtected(ManageUsers, 'setGroupsOfUser')
    def setGroupsOfUser(self, groupnames, username):
        """Sets the groups of a user"""
        user = self.getUserById(username)
        oldgroups = user.getGroups()
        # uniquify
        dict = {}
        for u in groupnames: dict[u] = None
        groupnames = dict.keys()
        # update info in user
        user._setGroups(groupnames)
        # update info in groups
        addgroups = filter(lambda g,o=oldgroups: g not in o, groupnames)
        delgroups = filter(lambda g,n=groupnames: g not in n, oldgroups)
        for groupname in addgroups:
            group = self.getGroupById(groupname)
            group._addUsers((username,))
        for groupname in delgroups:
            group = self.getGroupById(groupname)
            group._delUsers((username,))

    security.declareProtected(ManageUsers, 'addGroupsToUser')
    def addGroupsToUser(self, groupnames, username):
        """Adds one user to the groups"""
        # uniquify
        dict = {}
        for u in groupnames: dict[u] = None
        groupnames = dict.keys()
        # check values
        user = self.getUserById(username)
        oldgroups = user.getGroups()
        for groupname in groupnames:
            if groupname in oldgroups:
                raise ValueError, 'Group "%s" already exists' % groupname
        # update info in user
        user._addGroups(groupnames)
        # update info in groups
        for groupname in groupnames:
            group = self.getGroupById(groupname)
            group._addUsers((username,))

    security.declareProtected(ManageUsers, 'delGroupsFromUser')
    def delGroupsFromUser(self, groupnames, username):
        """Removes one user from the groups"""
        # uniquify
        dict = {}
        for u in groupnames: dict[u] = None
        groupnames = dict.keys()
        # check values
        user = self.getUserById(username)
        oldgroups = user.getGroups()
        for groupname in groupnames:
            if groupname not in oldgroups:
                raise ValueError, 'Group "%s" does not exist' % groupname
        # update info in user
        user._delGroups(groupnames)
        # update info in groups
        for groupname in groupnames:
            group = self.getGroupById(groupname)
            group._delUsers((username,))

    # This could be in the Group class but again we'd need
    # a way to call getUserById() from there.

    security.declareProtected(ManageUsers, 'setUsersOfGroup')
    def setUsersOfGroup(self, usernames, groupname):
        """Sets the users of the group"""
        # uniquify
        dict = {}
        for u in usernames: dict[u] = None
        usernames = dict.keys()
        #
        group = self.getGroupById(groupname)
        oldusers = group.getUsers()
        addusers = filter(lambda u,o=oldusers: u not in o, usernames)
        delusers = filter(lambda u,n=usernames: u not in n, oldusers)
        # update info in group
        group._setUsers(usernames)
        # update info in users
        for username in addusers:
            user = self.getUserById(username)
            user._addGroups((groupname,))
        for username in delusers:
            user = self.getUserById(username)
            user._delGroups((groupname,))

    security.declareProtected(ManageUsers, 'addUsersToGroup')
    def addUsersToGroup(self, usernames, groupname):
        """Adds the users to the group"""
        # uniquify
        dict = {}
        for u in usernames: dict[u] = None
        usernames = dict.keys()
        # check values
        group = self.getGroupById(groupname)
        oldusers = group.getUsers()
        for username in usernames:
            if username in oldusers:
                raise ValueError, 'User "%s" already exists' % username
        # update info in group
        group._addUsers(usernames)
        # update info in users
        for username in usernames:
            user = self.getUserById(username)
            user._addGroups((groupname,))

    security.declareProtected(ManageUsers, 'delUsersFromGroup')
    def delUsersFromGroup(self, usernames, groupname):
        """Removes the users from the group"""
        # uniquify
        dict = {}
        for u in usernames: dict[u] = None
        usernames = dict.keys()
        # check values
        group = self.getGroupById(groupname)
        oldusers = group.getUsers()
        for username in usernames:
            if username not in oldusers:
                raise ValueError, 'User "%s" does not exists' % username
        # update info in group
        group._delUsers(usernames)
        # update info in users
        for username in usernames:
            user = self.getUserById(username)
            user._delGroups((groupname,))

    #
    # Helper function
    #

    security.declareProtected(ManageUsers, 'list_local_userids')
    def list_local_userids(self):
        """Returns the list of user names or OverflowError"""
        mlu = getattr(aq_base(self), 'maxlistusers', None)
        if mlu is None:
            mlu = DEFAULTMAXLISTUSERS
        if mlu < 0:
            raise OverflowError
        usernames = self.getUserNames()
        if mlu != 0 and len(usernames) > mlu:
            raise OverflowError
        return usernames

    #
    # ZMI
    #

    manage_options = (
        (
        {'label':'User Groups', 'action':'manage_userGroups',},
        )
        )

    manage_userGroups = DTMLFile('zmi/mainGroup', globals(),
                                 management_view='User Groups')
    manage_addGroup = DTMLFile('zmi/addGroup', globals(),
                                 management_view='User Groups')
    manage_showGroup = DTMLFile('zmi/showGroup', globals(),
                                 management_view='User Groups')


    security.declareProtected(ManageUsers, 'manage_editGroups')
    def manage_editGroups(self,
                          submit_add_=None,
                          submit_add=None,
                          submit_edit=None,
                          submit_del=None,
                          groupname=None,
                          groupnames=[],
                          usernames=[],
                          title=None,
                          REQUEST=None, **kw):
        """Group management"""
        if submit_add_ is not None:
            return self.manage_addGroup(self, REQUEST)
        if submit_add is not None:
            return self._addGroup(groupname, usernames, title, REQUEST)
        if submit_edit is not None:
            return self._editGroup(groupname, usernames, title, REQUEST)
        if submit_del is not None:
            return self._delGroups(groupnames, REQUEST)
        raise ValueError, 'Incorrect submit'

    security.declarePrivate('_addGroup')
    def _addGroup(self, groupname, usernames=[], title='', REQUEST=None,
                  **kw):
        usernames = filter(None, map(lambda u,s=string.strip:s(u), usernames))
        if not groupname:
            return MessageDialog(
                title  ='Illegal value',
                message='A group name must be specified',
                action ='manage_userGroups')
        if self.getGroupById(groupname, None) is not None:
            return MessageDialog(
                title  ='Illegal value',
                message='A group named "%s" already exists' % groupname,
                action ='manage_userGroups')
        for username in usernames:
            if not self.getUserById(username):
                return MessageDialog(
                    title='Illegal value',
                    message='The user "%s" does not exist' % username,
                    action='manage_userGroups')

        self.userFolderAddGroup(groupname, title=title)
        self.setUsersOfGroup(usernames, groupname)

        if REQUEST is not None:
            return self.manage_userGroups(self, REQUEST)

    security.declarePrivate('_editGroup')
    def _editGroup(self, groupname, usernames=[], title='', REQUEST=None,
                   **kw):
        usernames = filter(None, map(lambda u,s=string.strip:s(u), usernames))
        if not groupname:
            return MessageDialog(
                title  ='Illegal value',
                message='A group name must be specified',
                action ='manage_userGroups')
        group = self.getGroupById(groupname, None)
        if group is None:
            return MessageDialog(
                   title='Illegal value',
                   message='The group "%s" does not exists' % groupname,
                   action='manage_userGroups')
        for username in usernames:
            if not self.getUserById(username):
                return MessageDialog(
                    title='Illegal value',
                    message='The user "%s" does not exist' % username,
                    action='manage_userGroups')

        group.setTitle(title)
        self.setUsersOfGroup(usernames, groupname)

        if REQUEST is not None:
            return self.manage_userGroups(self, REQUEST)

    security.declarePrivate('_delGroups')
    def _delGroups(self, groupnames, REQUEST=None, **kw):
        for groupname in groupnames:
            if self.getGroupById(groupname, None) is None:
                return MessageDialog(
                    title='Illegal value',
                    message='The group "%s" does not exists' % groupname,
                    action='manage_userGroups')

        self.userFolderDelGroups(groupnames)

        if REQUEST is not None:
            return self.manage_userGroups(self, REQUEST)


InitializeClass(BasicGroupFolderMixin)



class UserFolderWithGroups(UserFolder, BasicGroupFolderMixin):
    """
    Standard UserFolder with groups.

    Groups are a mapping between group names and lists of users.
    Groups can be used to affect roles to a lot of users
    at the same time, and to centralize management.
    """

    meta_type = 'User Folder With Groups'
    title = 'User Folder With Groups'

    security = ClassSecurityInfo()

    def __init__(self):
        UserFolder.__init__(self)
        self.groups = PersistentMapping()

    #
    # Implementation of groups
    #

    security.declareProtected(ManageUsers, 'userFolderAddGroup')
    def userFolderAddGroup(self, groupname, title='', **kw):
        """Creates a group"""
        if self.groups.has_key(groupname):
            raise ValueError, 'Group "%s" already exists' % groupname
        a = 'before: groupname %s groups %s' % (groupname, self.groups)
        group = apply(Group, (groupname,), kw)
        group.setTitle(title)
        self.groups[groupname] = group

    security.declareProtected(ManageUsers, 'userFolderDelGroups')
    def userFolderDelGroups(self, groupnames):
        """Deletes groups"""
        for groupname in groupnames:
            usernames = self.getGroupById(groupname).getUsers()
            self.delUsersFromGroup(usernames, groupname)
            del self.groups[groupname]

    security.declareProtected(ManageUsers, 'getGroupNames')
    def getGroupNames(self):
        """Returns a list of group names"""
        return tuple(self.groups.keys())

    security.declareProtected(ManageUsers, 'getGroupById')
    def getGroupById(self, groupname, default=_marker):
        """Returns the given group"""
        try:
            group = self.groups[groupname]
        except KeyError:
            if default is _marker: raise
            return default
        return group

    #
    # Overriden UserFolder methods
    #

    security.declarePrivate('_doAddUser')
    def _doAddUser(self, name, password, roles, domains, groups=(), **kw):
        """Creates a new user"""
        apply(UserFolder._doAddUser, (self, name, password, roles, domains), kw)
        self.setGroupsOfUser(groups, name)

    security.declarePrivate('_doDelUsers')
    def _doDelUsers(self, names):
        """Deletes one or more users."""
        for username in names:
            user = self.getUser(username)
            if user is None:
                raise KeyError, 'User "%s" does not exist' % username
            groupnames = user.getGroups()
            self.delGroupsFromUser(groupnames, username)
        UserFolder._doDelUsers(self, names)

    security.declarePrivate('_doChangeUser')
    def _doChangeUser(self, name, password, roles, domains, groups=None, **kw):
        apply(UserFolder._doChangeUser, (self, name, password, roles, domains), kw)
        if groups is not None:
            self.setGroupsOfUser(groups, name)

    #
    # ZMI overrides
    #

    manage_options = (
        UserFolder.manage_options[:1] +        # Contents
        BasicGroupFolderMixin.manage_options + # User Groups
        UserFolder.manage_options[1:]          # etc.
        )


    security.declarePrivate('_add_User')
    _add_User=DTMLFile('zmi/addUser', globals(),
                       remote_user_mode__=_remote_user_mode)

    security.declarePrivate('_editUser')
    _editUser = DTMLFile('zmi/editUser', globals(),
                         remote_user_mode__ = _remote_user_mode)

    security.declareProtected(ManageUsers, 'manage_users')
    def manage_users(self, submit=None, REQUEST=None, RESPONSE=None):
        """This method handles operations on users for the web based forms
           of the ZMI. Application code (code that is outside of the forms
           that implement the UI of a user folder) are encouraged to use
           manage_std_addUser"""

        if submit=='Add':
            name    =reqattr(REQUEST, 'name')
            password=reqattr(REQUEST, 'password')
            confirm =reqattr(REQUEST, 'confirm')
            roles   =reqattr(REQUEST, 'roles')
            domains =reqattr(REQUEST, 'domains')
            groups  =reqattr(REQUEST, 'groupnames')
            return self._addUser(name,password,confirm,roles,domains,REQUEST,groups)

        if submit=='Change':
            name    =reqattr(REQUEST, 'name')
            password=reqattr(REQUEST, 'password')
            confirm =reqattr(REQUEST, 'confirm')
            roles   =reqattr(REQUEST, 'roles')
            domains =reqattr(REQUEST, 'domains')
            groups  =reqattr(REQUEST, 'groupnames')
            return self._changeUser(name,password,confirm,roles,
                                    domains,REQUEST,groups)

        return UserFolder.manage_users(self, submit, REQUEST, RESPONSE)

    security.declarePrivate('_addUser')
    def _addUser(self,name,password,confirm,roles,domains,REQUEST=None,
                 groups=None):
        if not roles: roles=[]
        if not domains: domains=[]
        if not groups: groups=[]
        # error cases
        if ((not name) or
            (not password or not confirm) or
            (self.getUser(name) or (self._emergency_user and
                                    name == self._emergency_user.getUserName())) or
            ((password or confirm) and (password != confirm)) or
            (domains and not self.domainSpecValidate(domains))
            ):
            return UserFolder._addUser(self,name,password,confirm,roles,
                                       domains,REQUEST)

        self._doAddUser(name, password, roles, domains, groups)

        if REQUEST is not None:
            return self._mainUser(self, REQUEST)

    security.declarePrivate('_changeUser')
    def _changeUser(self,name,password,confirm,roles,domains,REQUEST=None,
                    groups=None):
        if password == 'password' and confirm == 'pconfirm':
            password = confirm = None
        if not roles: roles=[]
        if not domains: domains=[]
        # error cases
        if ((not name) or
            (password == confirm == '') or
            (not self.getUser(name)) or
            ((password or confirm) and (password != confirm)) or
            (domains and not self.domainSpecValidate(domains))
            ):
            return UserFolder._changeUser(self,name,password,confirm,roles,
                                          domains,REQUEST)

        self._doChangeUser(name, password, roles, domains, groups)

        if REQUEST is not None:
            return self._mainUser(self, REQUEST)





InitializeClass(UserFolderWithGroups)



def addUserFolderWithGroups(dispatcher, id=None, REQUEST=None):
    """ Adds a User Folder With Groups """
    f = UserFolderWithGroups()
    container = dispatcher.Destination()
    container._setObject('acl_users', f)
    container.__allow_groups__ = f
    if REQUEST is not None:
        dispatcher.manage_main(dispatcher, REQUEST)



# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
