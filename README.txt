This product adds the notion of groups of users.

Groups provide a level of indirection in the user -> roles mapping,
which gives greater flexibility.

The groups are defined and managed in the User Folder. They are then
used at the local roles level, where you can define an additionnal
mapping of groups -> roles, thus giving the users who belong to these
groups additionnal local roles.

Two special groups, 'role:Anonymous' and 'role:Authenticated', are
always available in local roles and represent respectively all the users
(including anonymous), and the succesfully authenticated ones.

Use for workgroups

  There are several ways to do workgroups with Zope, and NuxUserGroups
  improves on them.

  Standard Zope v1

      - one role per workgroup

      - local mapping of role -> permissions

    A simple notion of workgroup can be defined using one role per
    workgroup, with all these roles having no permission mapping at the
    toplevel. To define the workgroup membership you assign the roles to
    the users in the User Folder. Then for each different workgroup
    folder, you assign the correct permissions to the role corresponding
    to that workgroup, so that it can access and change documents.

    This method works but is pretty unmanageable: there are now a lot of
    redundant roles in the 'Security' tab, and you have be sure all your
    role -> permissions mapping are correct everywhere. Also there is
    absolutely no way to factor workgroup membership in the case where
    your workgroups are of the form:

      - WG1: U1, U2, U3, U4, U5, U6, U7, U8

      - WG2: U1, U2, U3, U4, U5, U6, U9

      - WG3: U1, U2, U3, U4, U5, U6, U10, U11

  Standard Zope v2

      - one role

      - local mapping of users -> role

    You define a single 'Workgroup Member' role with adequate
    permissions to access and change documents. Then for each different
    workgroup folder you assign local roles mapping the users of that
    workgroup to the role 'Workgroup Member'.

    This method is better than the first but means that you have to
    manage the workgroup membership locally in the folders instead of in
    a central place. And as above, you cannot factor things.

  Zope + NuxUserGroups

      - one role

      - local mapping of group -> role

    Here you also define a single 'Workgroup Member' role with adequate
    permissions to access and change documents. You define groups of
    users as you wish in the User Folder. Then for each different
    workgroup folder you assign local group roles mapping the desired
    groups to the role 'Workgroup Member'.

Basic usage

  - unpack in you Products directory,

  - restart Zope,

  - add a 'User Folder With Groups' somewhere in your tree,

  - configure the groups in the 'User Groups' tab,

  - manage a folder's local group roles using the 'Local Roles' link in
    the 'Security' tab of the folder.

Product internals

  - defines a new UserFolder, called UserFolderWithGroups, where you can
    define the groups and what users belong to what groups,

  - patches BasicUser to add group support methods,

  - patches the the local roles management pages of the ZMI to define
    what groups have what local roles,

  - patches the local role machinery in BasicUser to take into account
    the groups when computing local roles,

  - patches the CMF Catalog Tool to take into account the groups. This
    is needed because the Catalog Tool automatically filters the objects
    returned from a catalog query to keep only those on which the user
    has View permission.

Caveat

  This product is not compatible with other products that may patch
  local roles support in BasicUser, for instance LRBlacklist. **Do not
  use them together.**

TODO

  - Add group support to other User Folders: LDAPUserFolder,
    exUserFolder...
