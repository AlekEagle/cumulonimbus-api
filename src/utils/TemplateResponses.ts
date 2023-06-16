export namespace Errors {
  export class Permissions implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INSUFFICIENT_PERMISSIONS_ERROR";
    public readonly message: string = "Missing Permissions";
    constructor() {}
  }

  export class InvalidUser implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_USER_ERROR";
    public readonly message: string = "Invalid User";
    constructor() {}
  }

  export class InvalidUsername implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_USERNAME_ERROR";
    public readonly message: string = "Invalid Username";
    constructor() {}
  }

  export class InvalidPassword implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_PASSWORD_ERROR";
    public readonly message: string = "Invalid Password";
    constructor() {}
  }

  export class PasswordsDoNotMatch implements Cumulonimbus.Structures.Error {
    public readonly code: string = "PASSWORDS_DO_NOT_MATCH_ERROR";
    public readonly message: string = "Passwords Do Not Match";
    constructor() {}
  }

  export class InvalidEmail implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_EMAIL_ERROR";
    public readonly message: string = "Invalid Email";
    constructor() {}
  }

  export class InvalidSession implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_SESSION_ERROR";
    public readonly message: string = "Invalid Session";
    constructor() {}
  }

  export class InvalidDomain implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_DOMAIN_ERROR";
    public readonly message: string = "Invalid Domain";
    constructor() {}
  }

  export class InvalidSubdomain implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_SUBDOMAIN_ERROR";
    public readonly message: string = "Invalid Subdomain";
    constructor(public readonly parsedDomain: string) {}
  }

  export class InvalidFile implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_FILE_ERROR";
    public readonly message: string = "Invalid File";
    constructor() {}
  }

  export class InvalidInstruction implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_INSTRUCTION_ERROR";
    public readonly message: string = "Invalid Instruction";
    constructor() {}
  }

  export class InvalidEndpoint implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INVALID_ENDPOINT_ERROR";
    public readonly message: string = "Invalid Endpoint";
    constructor() {}
  }

  export class SubdomainNotSupported implements Cumulonimbus.Structures.Error {
    public readonly code: string = "SUBDOMAIN_NOT_SUPPORTED_ERROR";
    public readonly message: string = "Subdomain Not Supported";
    constructor() {}
  }

  export class DomainExists implements Cumulonimbus.Structures.Error {
    public readonly code: string = "DOMAIN_EXISTS_ERROR";
    public readonly message: string = "Domain Exists";
    constructor() {}
  }

  export class UserExists implements Cumulonimbus.Structures.Error {
    public readonly code: string = "USER_EXISTS_ERROR";
    public readonly message: string = "User Exists";
    constructor() {}
  }

  export class InstructionExists implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INSTRUCTION_EXISTS_ERROR";
    public readonly message: string = "Instruction Exists";
    constructor() {}
  }

  export class MissingFields implements Cumulonimbus.Structures.Error {
    public readonly code: string = "MISSING_FIELDS_ERROR";
    public readonly message: string = "Missing Fields";
    constructor(public readonly fields: string[]) {}
  }

  export class Banned implements Cumulonimbus.Structures.Error {
    public readonly code: string = "BANNED_ERROR";
    public readonly message: string = "Banned";
    constructor() {}
  }

  export class BodyTooLarge implements Cumulonimbus.Structures.Error {
    public readonly code: string = "BODY_TOO_LARGE_ERROR";
    public readonly message: string = "Body Too Large";
    constructor() {}
  }

  export class RateLimited implements Cumulonimbus.Structures.Error {
    public readonly code: string = "RATELIMITED_ERROR";
    public readonly message: string =
      "You Have Been Ratelimited. Please Try Again Later.";
    constructor() {}
  }

  export class Internal implements Cumulonimbus.Structures.Error {
    public readonly code: string = "INTERNAL_SERVER_ERROR";
    public readonly message: string = "Internal Server Error";
    constructor() {}
  }
}

export namespace Success {
  export class DeleteUser implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_USER_SUCCESS";
    public readonly message: string = "User Successfully Deleted";
    constructor() {}
  }

  export class DeleteUsers implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_USERS_SUCCESS";
    public readonly message: string = "Users Successfully Deleted";
    constructor(public readonly count: number) {}
  }

  export class DeleteFile implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_FILE_SUCCESS";
    public readonly message: string = "File Successfully Deleted";
    constructor() {}
  }

  export class DeleteFiles implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_FILES_SUCCESS";
    public readonly message: string = "Files Successfully Deleted";
    constructor(public readonly count: number) {}
  }

  export class DeleteSession implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_SESSION_SUCCESS";
    public readonly message: string = "Session Successfully Deleted";
    constructor() {}
  }

  export class DeleteSessions implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_SESSIONS_SUCCESS";
    public readonly message: string = "Sessions Successfully Deleted";
    constructor(public readonly count: number) {}
  }

  export class DeleteDomain implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_DOMAIN_SUCCESS";
    public readonly message: string = "Domain Successfully Deleted";
    constructor() {}
  }

  export class DeleteDomains implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_DOMAINS_SUCCESS";
    public readonly message: string = "Domains Successfully Deleted";
    constructor(public readonly count: number) {}
  }

  export class DeleteInstruction implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_INSTRUCTION_SUCCESS";
    public readonly message: string = "Instruction Successfully Deleted";
    constructor() {}
  }

  export class DeleteInstructions implements Cumulonimbus.Structures.Success {
    public readonly code: string = "DELETE_INSTRUCTIONS_SUCCESS";
    public readonly message: string = "Instructions Successfully Deleted";
    constructor(public readonly count: number) {}
  }
}
