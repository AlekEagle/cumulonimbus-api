export enum PermissionFlags {
  ALL = 1 << 0,
  UPLOAD_FILE = 1 << 1,
  USER_ACCOUNT_READ = 1 << 2,
  USER_ACCOUNT_MODIFY = 1 << 3,
  USER_SESSION_READ = 1 << 4,
  USER_SESSION_MODIFY = 1 << 5,
  USER_SESSION_CREATE = 1 << 6,
  USER_FILE_READ = 1 << 7,
  USER_FILE_MODIFY = 1 << 8,
}

export enum PermissionGroups {
  USER_ACCOUNT = PermissionFlags.USER_ACCOUNT_READ |
    PermissionFlags.USER_ACCOUNT_MODIFY,
  USER_SESSION = PermissionFlags.USER_SESSION_READ |
    PermissionFlags.USER_SESSION_MODIFY |
    PermissionFlags.USER_SESSION_CREATE,
  USER_FILE = PermissionFlags.USER_FILE_READ | PermissionFlags.USER_FILE_MODIFY,
}
