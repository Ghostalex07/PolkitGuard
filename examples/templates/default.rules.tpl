[polkit_default]
# Default polkit rule template
[unix-user:USERNAME]
Action=ACTION_NAME
ResultAny=auth_admin

[unix-group:wheel]
Action=ACTION_NAME
ResultAny=auth_admin_keep

[unix-group:admin]
Action=ACTION_NAME
ResultAny=auth_admin_keep