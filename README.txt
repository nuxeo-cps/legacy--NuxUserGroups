NuxUserwithgroups

  This product adds the notion of groups of users.

  For now, the groups are only used in the local roles, where you can
  define an additionnal mapping of groups -> roles. This gives the users
  who belong to these groups additionnal local roles.

  The product:

    - defines a new UserFolder, called UserwithgroupsFolder, where
      you can define the groups and what users belong to what groups,

    - provides an additionnal interface in the local roles management
      page of the ZMI to define what groups have what local roles
      (monkeypatch),

    - patches the local role machinery to take into account the groups.
