NuxUserGroups

  This product adds the notion of groups of users.

  For now, the groups are only used in the local roles, where you can
  define an additionnal mapping of groups -> roles. This gives the users
  who belong to these groups additionnal local roles.

  The product:

    - defines a new UserFolder, called UserFolderWithGroups, where
      you can define the groups and what users belong to what groups,

    - patches BasicUser to add group support methods,

    - patches the the local roles management pages of the ZMI to
      define what groups have what local roles,

    - patches the local role machinery in BasicUser to take into
      account the groups when computing local roles.
