# Copyright (c) 2002 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2002 Préfecture du Bas-Rhin, France
# Author: Florent Guillaume <mailto:fg@nuxeo.com>
#
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
# $Id$

"""
  CatalogToolWithGroups
  Patches CMF Catalog Tool to add groups support in allowedRolesAndUsers.
"""

__version__ = '$Revision$'[11:-2]

# The patching should now be done in CPS. Try to reimport the methods here
# for compatibility.

_cmf_localroles_patch = 0
try:
    from NuxCPS.utils import _allowedRolesAndUsers, _getAllowedRolesAndUsers
    from CMFCore.utils import mergedLocalRoles
    _cmf_localroles_patch = 1
except ImportError:
    pass

try:
    from NuxCPS3.utils import _allowedRolesAndUsers, _getAllowedRolesAndUsers
    from CMFCore.utils import mergedLocalRoles
    _cmf_localroles_patch = 1
except ImportError:
    pass

if not _cmf_localroles_patch:
    # This is used outside CPS or with older versions,
    # so we do the patching here!
    from zLOG import LOG, INFO, DEBUG

    from AccessControl.PermissionRole import rolesForPermissionOn

    from Products.CMFCore.CatalogTool import IndexableObjectWrapper, \
        CatalogTool

    from Products.CMFCore.utils import getToolByName

    LOG('NuxUserGroups.CatalogToolWithGroups', INFO, 'Patching CMF')

    def mergedLocalRoles(object, withgroups=0, withpath=0):
        """Return a merging of object and its ancestors' __ac_local_roles__.

        When called with withgroups=1, the keys are
        of the form user:foo and group:bar.
        When called with withpath=1, the path corresponding
        to the object where the role takes place is added
        with the role in the result. In this case of the form :
        {'user:foo': [{'url':url, 'roles':[Role0, Role1]},
                    {'url':url, 'roles':[Role1]}],..}.
        """
        # Modified from AccessControl.User.getRolesInContext().

        if withpath:
            utool = getToolByName(object, 'portal_url')
        merged = {}
        object = getattr(object, 'aq_inner', object)

        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                if withpath:
                    obj_url = utool.getRelativeUrl(object)
                for k, v in dict.items():
                    if withgroups:
                        k = 'user:'+k # groups
                    if merged.has_key(k):
                        if withpath:
                            merged[k].append({'url':obj_url,'roles':v})
                        else:
                            merged[k] = merged[k] + v
                    else:
                        if withpath:
                            merged[k] = [{'url':obj_url,'roles':v}]
                        else:
                            merged[k] = v
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    if withpath:
                        obj_url = utool.getRelativeUrl(object)
                    for k, v in dict.items():
                        k = 'group:'+k
                        if merged.has_key(k):
                            if withpath:
                                merged[k].append({'url':obj_url,'roles':v})
                            else:
                                merged[k] = merged[k] + v
                        else:
                            if withpath:
                                merged[k] = [{'url':obj_url,'roles':v}]
                            else:
                                merged[k] = v
            # end groups
            if hasattr(object, 'aq_parent'):
                object = object.aq_parent
                object = getattr(object, 'aq_inner', object)
                continue
            if hasattr(object, 'im_self'):
                object = object.im_self
                object = getattr(object, 'aq_inner', object)
                continue
            break

        return merged



    # belongs to CPS API too
    def _allowedRolesAndUsers(ob):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        allowed = {}
        for r in rolesForPermissionOn('View', ob):
            allowed[r] = 1
        localroles = mergedLocalRoles(ob, withgroups=1) # groups
        for user_or_group, roles in localroles.items():
            for role in roles:
                if allowed.has_key(role):
                    allowed[user_or_group] = 1
        if allowed.has_key('Owner'):
            del allowed['Owner']
        return list(allowed.keys())

    def allowedRolesAndUsers(self):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        ob = self._IndexableObjectWrapper__ob # Eeek, manual name mangling
        return _allowedRolesAndUsers(ob)
    IndexableObjectWrapper.allowedRolesAndUsers = allowedRolesAndUsers


    # belongs to API too
    def _getAllowedRolesAndUsers(user):
        result = list(user.getRoles())
        result.append('Anonymous')
        result.append('user:%s' % user.getUserName())
        # deal with groups
        getGroups = getattr(user, 'getGroups', None)
        if getGroups is not None:
            groups = user.getGroups() + ('role:Anonymous',)
            if 'Authenticated' in result:
                groups = groups + ('role:Authenticated',)
            for group in groups:
                result.append('group:%s' % group)
        # end groups
        return result

    def _listAllowedRolesAndUsers(self, user):
        return _getAllowedRolesAndUsers(user)
    CatalogTool._listAllowedRolesAndUsers = _listAllowedRolesAndUsers
