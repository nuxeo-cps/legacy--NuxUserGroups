# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# See licence info at the end of this file.
# $Id$

"""
  Usergroups
"""

__version__ = '$Revision$'[11:-2]


# In some places where "group" should be used we actually
# say "usergroup" to prevent clashes with some existing
# UserFolders that use "group" for "role".


import string, re, urllib, os

from Globals import InitializeClass, DTMLFile, MessageDialog, \
     PersistentMapping
from AccessControl import ClassSecurityInfo, getSecurityManager, \
     Permissions
from AccessControl.User import User, UserFolder, reqattr, _remote_user_mode
from AccessControl.PermissionRole import _what_not_even_god_should_do

ManageUsers = Permissions.manage_users

class Userwithgroups(User):
    """
    A User that can belong to groups.
    """

    # Security is dealt with by BasicUser using
    # __allow_access_to_unprotected_subobjects__

    def __init__(self,name,password,roles,domains):
        User.__init__(self,name,password,roles,domains)
        self._usergroups = [] # managed by user folder

    # only a shortcut to avoid going to the user folder
    def getGroups(self):
        """Returns the groups assigned to the user."""
        return tuple(self._usergroups)

##     def getRoles(self):
##         """Return the list of roles assigned to a user."""
##         # also examine the groups we belong to ???
##         # can a group define roles globaly ???
##         # -> not yet.
##         return User.getRoles(self)

    def getRolesInContext(self, object):
        """Return the list of roles assigned to the user,
           including local roles assigned in context of
           the passed in object."""
        name=self.getUserName()
        groups=self.getGroups() #
        roles=self.getRoles()
        local={}
        object=getattr(object, 'aq_inner', object)
        while 1:
            local_roles = getattr(object, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles=local_roles()
                dict=local_roles or {}
                for r in dict.get(name, []):
                    local[r]=1
            # deal with groups
            local_group_roles = getattr(object, '__ac_local_group_roles__', None)
            if local_group_roles:
                if callable(local_group_roles):
                    local_group_roles=local_group_roles()
                dict=local_group_roles or {}
                for g in groups:
                    for r in dict.get(g, []):
                        local[r]=1
            #
            inner = getattr(object, 'aq_inner', object)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                object = parent
                continue
            if hasattr(object, 'im_self'):
                object=object.im_self
                object=getattr(object, 'aq_inner', object)
                continue
            break
        roles=list(roles) + local.keys()
        return roles


    def allowed(self, object, object_roles=None):
        """Check whether the user has access to object. The user must
           have one of the roles in object_roles to allow access."""

        if object_roles is _what_not_even_god_should_do: return 0

        # Short-circuit the common case of anonymous access.
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

        # Provide short-cut access if object is protected by 'Authenticated'
        # role and user is not nobody
        if 'Authenticated' in object_roles and (
            self.getUserName() != 'Anonymous User'):
            return 1

        # Check for ancient role data up front, convert if found.
        # This should almost never happen, and should probably be
        # deprecated at some point.
        if 'Shared' in object_roles:
            object_roles = self._shared_roles(object)
            if object_roles is None or 'Anonymous' in object_roles:
                return 1

        # Check for a role match with the normal roles given to
        # the user, then with local roles only if necessary. We
        # want to avoid as much overhead as possible.
        user_roles = self.getRoles()
        for role in object_roles:
            if role in user_roles:
                if self._check_context(object):
                    return 1
                return None

        # Still have not found a match, so check local roles. We do
        # this manually rather than call getRolesInContext so that
        # we can incur only the overhead required to find a match.
        inner_obj = getattr(object, 'aq_inner', object)
        user_name = self.getUserName()
        groups = self.getGroups() #
        while 1:
            local_roles = getattr(inner_obj, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles = local_roles()
                dict = local_roles or {}
                local_roles = dict.get(user_name, [])
                for role in object_roles:
                    if role in local_roles:
                        if self._check_context(object):
                            return 1
                        return 0
            # deal with groups
            local_group_roles = getattr(inner_obj, '__ac_local_group_roles__', None)
            if local_group_roles:
                if callable(local_group_roles):
                    local_group_roles = local_group_roles()
                dict = local_group_roles or {}
                for g in groups:
                    local_group_roles = dict.get(g, [])
                    if local_group_roles:
                        for role in object_roles:
                            if role in local_group_roles:
                                if self._check_context(object):
                                    return 1
                                return 0
            #
            inner = getattr(inner_obj, 'aq_inner', inner_obj)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                inner_obj = parent
                continue
            if hasattr(inner_obj, 'im_self'):
                inner_obj=inner_obj.im_self
                inner_obj=getattr(inner_obj, 'aq_inner', inner_obj)
                continue
            break
        return None


class UserwithgroupsFolder(UserFolder):
    """
    A UserwithgroupsFolder is a UserFolder where users
    can be organized into groups.
    """

    meta_type = 'Userwithgroups Folder'

    security = ClassSecurityInfo()

    # override
    def __init__(self):
        UserFolder.__init__(self)
        # We use two mappings for speed.
        # These mappings contain lists, which of course
        # mustn't be changed in place...
        # Moreover, the User object has a usergroups attribute
        # that mirrors groupsofuser, for speed too.
        self.groupsofuser = PersistentMapping() # user -> groups
        self.usersofgroup = PersistentMapping() # group -> users

    # override
    security.declarePrivate('_doAddUser')
    def _doAddUser(self, name, password, roles, domains, groups=(), **kw):
        """Creates a new user"""
        if password is not None and self.encrypt_passwords:
            password = self._encryptPassword(password)
        self.data[name] = Userwithgroups(name,password,roles,domains)
        self.setGroupsOfUser(name, groups)

    # override
    security.declarePrivate('_doDelUsers')
    def _doDelUsers(self, names):
        """Deletes one or more users."""
        for name in names:
            groups = self.groupsofuser.get(name, [])
            self.delUserFromGroups(name, groups)
            if self.groupsofuser.has_key(name): del self.groupsofuser[name]
        return UserFolder._doDelUsers(self, names)

    # override
    security.declarePrivate('_doChangeUser')
    def _doChangeUser(self, name, password, roles, domains, groups=(), **kw):
        self.setGroupsOfUser(name, groups)
        return apply(UserFolder._doChangeUser,
                     (self, name, password, roles, domains), kw)


    security.declareProtected(ManageUsers, 'userFolderAddGroup')
    def userFolderAddGroup(self, groupname):
        """Creates a group"""
        if not self.usersofgroup.has_key(groupname):
            self.usersofgroup[groupname] = []

    security.declareProtected(ManageUsers, 'userFolderDelGroups')
    def userFolderDelGroups(self, groupnames):
        """Deletes groups"""
        for groupname in groupnames:
            if self.usersofgroup.has_key(groupname):
                usernames = self.usersofgroup[groupname]
                self.delUsersFromGroup(usernames, groupname)
                del self.usersofgroup[groupname]

    security.declareProtected(ManageUsers, 'listGroupNames')
    def listGroupNames(self):
        """Returns a list of group names"""
        return self.usersofgroup.keys()
        #return ('debuggroup1', 'debuggroup2')

    security.declareProtected(ManageUsers, 'listUsersOfGroup')
    def listUsersOfGroup(self, groupname):
        """Returns the list of user names in the group"""
        return tuple(self.usersofgroup[groupname])

    security.declareProtected(ManageUsers, 'listUsersFromGroup')
    def listGroupsOfUser(self, username):
        """Returns the list of groups of the user"""
        return tuple(self.groupsofuser.get(username,[]))


##         user=self.data[name]
##         if password is not None:
##             if self.encrypt_passwords:
##                 password = self._encryptPassword(password)
##             user.__=password
##         user.roles=roles
##         user.domains=domains

    security.declareProtected(ManageUsers, 'setUsersOfGroup')
    def setUsersOfGroup(self, usernames, groupname):
        """Sets the users of the group"""
        users = self.usersofgroup[groupname]
        addusers = filter(lambda u,o=users: u not in o, usernames)
        delusers = filter(lambda u,n=usernames: u not in n, users)
        # add those not already there
        for username in addusers:
            groups = self.groupsofuser.get(username, [])
            groups.append(groupname)
            self.groupsofuser[username] = groups
            self.data[username]._usergroups = list(groups)
        # remove those not needed
        for username in delusers:
            groups = self.groupsofuser[username]
            groups.remove(groupname)
            self.groupsofuser[username] = groups # del if empty ?
            self.data[username]._usergroups = list(groups)
        self.usersofgroup[groupname] = list(usernames)

    security.declareProtected(ManageUsers, 'setGroupsOfUser')
    def setGroupsOfUser(self, username, groupnames): # note arg order
        """Sets the groups of a user"""
        groups = self.groupsofuser.get(username, [])
        addgroups = filter(lambda g,o=groups: g not in o, groupnames)
        delgroups = filter(lambda g,n=groupnames: g not in n, groups)
        # add those not already there
        for groupname in addgroups:
            users = self.usersofgroup[groupname]
            users.append(username)
            self.usersofgroup[groupname] = users
        # remove those not needed
        for groupname in delgroups:
            users = self.usersofgroup[groupname]
            users.remove(username)
            self.usersofgroup[groupname] = users
        self.groupsofuser[username] = groupnames
        self.data[username]._usergroups = list(groupnames)

    security.declareProtected(ManageUsers, 'addUsersToGroup')
    def addUsersToGroup(self, usernames, groupname):
        """Adds the users to one group"""
        users = list(self.usersofgroup[groupname])
        for username in usernames:
            if not username in users:
                users.append(username)
        self.setUsersOfGroup(users, groupname)

    security.declareProtected(ManageUsers, 'addUserToGroups')
    def addUserToGroups(self, username, groupnames):
        """Adds one user to the groups"""
        groups = list(self.groupsofuser.get(username, []))
        for groupname in groupnames:
            if not groupname in groups:
                groups.append(groupname)
        self.setGroupsOfUser(username, groups)

    security.declareProtected(ManageUsers, 'delUsersFromGroup')
    def delUsersFromGroup(self, usernames, groupname):
        """Removes the users from one group"""
        users = self.usersofgroup[groupname]
        users = filter(lambda u,d=usernames: u not in d, users)
        self.setUsersOfGroup(users, groupname)

    security.declareProtected(ManageUsers, 'delUserFromGroups')
    def delUserFromGroups(self, username, groupnames):
        """Removes one user from the groups"""
        groups = self.groupsofuser.get(username, [])
        groups = filter(lambda g,d=groupnames: g not in d, groups)
        self.setGroupsOfUser(username, groups)

    #
    # ZMI
    #

    manage_options= (UserFolder.manage_options[:1] + # Contents
                     ({'label':'Usergroups', 'action':'manage_usergroups'},) +
                     UserFolder.manage_options[1:])

    # override
    security.declarePrivate('_add_User')
    _add_User=DTMLFile('zmi/addUser', globals(),
                       remote_user_mode__=_remote_user_mode)

    # override
    security.declarePrivate('_editUser')
    _editUser = DTMLFile('zmi/editUser', globals(),
                         remote_user_mode__ = _remote_user_mode)

    # override
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

    # override
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

    # override
    security.declarePrivate('_changeUser')
    def _changeUser(self,name,password,confirm,roles,domains,REQUEST=None,
                    groups=None):
        if password == 'password' and confirm == 'pconfirm':
            password = confirm = None
        if not roles: roles=[]
        if not domains: domains=[]
        if not groups: groups=[]
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


    security.declarePrivate('_add_Group')
    _add_Group = DTMLFile('zmi/addGroup', globals())

    security.declarePrivate('_editGroup')
    _editGroup = DTMLFile('zmi/editGroup', globals())

    security.declarePrivate('_mainGroups')
    _mainGroups = DTMLFile('zmi/mainGroups', globals())

    security.declareProtected(ManageUsers, 'manage_usergroups')
    def manage_usergroups(self, submit=None, REQUEST=None):
        """Management of user groups."""
        if submit == 'Add...':
            return self._add_Group(self, REQUEST)

        if submit=='Edit':
            return self._editGroup(self, REQUEST)

        if submit=='Add':
            groupname = reqattr(REQUEST, 'groupname')
            usernames = reqattr(REQUEST, 'usernames')
            return self._addGroup(groupname, usernames, REQUEST)

        if submit=='Change':
            groupname = reqattr(REQUEST, 'groupname')
            usernames = reqattr(REQUEST, 'usernames')
            return self._changeGroup(groupname, usernames, REQUEST)

        if submit=='Delete':
            groupnames = reqattr(REQUEST, 'groupnames')
            return self._delGroups(groupnames, REQUEST)

        return self._mainGroups(self, REQUEST)

    security.declarePrivate('_addGroup')
    def _addGroup(self, groupname, usernames=None, REQUEST=None):
        if not usernames: usernames=[]
        usernames = filter(None, map(lambda u,s=string.strip:s(u), usernames))
        if self.usersofgroup.has_key(groupname):
            return MessageDialog(
                   title='Illegal value', 
                   message='A group with the specified name already exists',
                   action='manage_usergroups')
        for username in usernames:
            if not self.getUser(username):
                return MessageDialog(
                    title='Illegal value', 
                    message='The user "%s" does not exist' % username,
                    action='manage_usergroups')
        self.userFolderAddGroup(groupname)
        self.setUsersOfGroup(usernames, groupname)

        if REQUEST is not None:
            return self._mainGroups(self, REQUEST)

    security.declarePrivate('_changeGroup')
    def _changeGroup(self, groupname, usernames=None, REQUEST=None):
        if not usernames: usernames=[]
        usernames = filter(None, map(lambda u,s=string.strip:s(u), usernames))
        if not self.usersofgroup.has_key(groupname):
            return MessageDialog(
                   title='Illegal value', 
                   message='The group with the specified name does not exists',
                   action='manage_usergroups')
        for username in usernames:
            if not self.getUser(username):
                return MessageDialog(
                    title='Illegal value', 
                    message='The user "%s" does not exist' % username,
                    action='manage_usergroups')
        self.setUsersOfGroup(usernames, groupname)

        if REQUEST is not None:
            return self._mainGroups(self, REQUEST)

    security.declarePrivate('_delGroups')
    def _delGroups(self, groupnames, REQUEST=None):
        for groupname in groupnames:
            if not self.usersofgroup.has_key(groupname):
                return MessageDialog(
                    title='Illegal value', 
                    message='The group "%s" does not exists' % groupname,
                    action='manage_usergroups')
        self.userFolderDelGroups(groupnames)

        if REQUEST is not None:
            return self._mainGroups(self, REQUEST)


InitializeClass(UserwithgroupsFolder)


def addUserwithgroupsFolder(dispatcher, id=None, REQUEST=None):
    """ Adds a UserwithgroupsFolder """
    f = UserwithgroupsFolder()
    container = dispatcher.Destination()
    try:    container._setObject('acl_users', f)
    except: return MessageDialog(
                   title  ='Item Exists',
                   message='This object already contains a User Folder',
                   action ='%s/manage_main' % REQUEST.URL1)
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
