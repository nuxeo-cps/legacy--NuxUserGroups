# (c) 2002 Nuxeo SARL <http://nuxeo.com>
# (c) 2002 Florent Guillaume <mailto:fg@nuxeo.com>
# (c) 2002 Préfecture du Bas-Rhin, France
# See license info at the end of this file.
# $Id$

"""
  CatalogToolWithGroups
  Patches CMF Catalog Tool to add groups support in allowedRolesAndUsers.
"""

__version__ = '$Revision$'[11:-2]

from zLOG import LOG, INFO

from AccessControl.PermissionRole import rolesForPermissionOn

from Products.CMFCore.CatalogTool import IndexableObjectWrapper, \
     CatalogTool


LOG('NuxUserGroups.CatalogToolWithGroups', INFO, 'Patching CatalogTool')


def mergedLocalRoles(object, withgroups=0):
    """Returns a merging of object and its ancestors'
    __ac_local_roles__.
    When called with withgroups=1, the keys are
    of the form user:foo and group:bar."""
    # Modified from AccessControl.User.getRolesInContext().
    merged = {}
    object = getattr(object, 'aq_inner', object)
    while 1:
        if hasattr(object, '__ac_local_roles__'):
            dict = object.__ac_local_roles__ or {}
            if callable(dict): dict = dict()
            for k, v in dict.items():
                if withgroups: k = 'user:'+k # groups
                if merged.has_key(k):
                    merged[k] = merged[k] + v
                else:
                    merged[k] = v
        # deal with groups
        if withgroups:
            if hasattr(object, '__ac_local_group_roles__'):
                dict = object.__ac_local_group_roles__ or {}
                if callable(dict): dict = dict()
                for k, v in dict.items():
                    k = 'group:'+k
                    if merged.has_key(k):
                        merged[k] = merged[k] + v
                    else:
                        merged[k] = v
        # end groups
        if hasattr(object, 'aq_parent'):
            object=object.aq_parent
            object=getattr(object, 'aq_inner', object)
            continue
        if hasattr(object, 'im_self'):
            object=object.im_self
            object=getattr(object, 'aq_inner', object)
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
        groups = self.getGroups() + ('role:Anonymous',)
        if 'Authenticated' in result:
            groups = groups + ('role:Authenticated',)
        for group in groups:
            result.append('group:%s' % group)
    # end groups
    return result

def _listAllowedRolesAndUsers(self, user):
    return _getAllowedRolesAndUsers(user)
CatalogTool._listAllowedRolesAndUsers = _listAllowedRolesAndUsers


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
