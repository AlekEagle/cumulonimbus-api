import type { SecondFactorType } from '../DB/SecondFactor.js';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types';

export namespace Errors {
  export class InsufficientPermissions
    implements Cumulonimbus.Structures.Error
  {
    public readonly code: string = 'INSUFFICIENT_PERMISSIONS_ERROR';
    public readonly message: string = 'Insufficient Permissions';
  }

  export class InvalidUser implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_USER_ERROR';
    public readonly message: string = 'Invalid User';
  }

  export class InvalidUsername implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_USERNAME_ERROR';
    public readonly message: string = 'Invalid Username';
  }

  export class Invalid2FAMethod implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_2FA_METHOD_ERROR';
    public readonly message: string = 'Invalid 2FA Method';
  }

  export class Invalid2FAResponse implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_2FA_RESPONSE_ERROR';
    public readonly message: string = 'Invalid 2FA Response';
  }

  export class Challenge2FARequired
    implements
      Cumulonimbus.Structures.Error,
      Cumulonimbus.Structures.SecondFactorChallenge
  {
    public readonly code: string = 'CHALLENGE_2FA_REQUIRED_ERROR';
    public readonly message: string = 'Challenge 2FA Required';
    constructor(
      public readonly token: string,
      public readonly exp: number,
      public readonly types: (SecondFactorType | 'backup')[],
      public readonly challenge?: PublicKeyCredentialRequestOptionsJSON,
    ) {}
  }

  export class InvalidPassword implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_PASSWORD_ERROR';
    public readonly message: string = 'Invalid Password';
  }

  export class PasswordsDoNotMatch implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'PASSWORDS_DO_NOT_MATCH_ERROR';
    public readonly message: string = 'Passwords Do Not Match';
  }

  export class InvalidEmail implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_EMAIL_ERROR';
    public readonly message: string = 'Invalid Email';
  }

  export class EmailNotVerified implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'EMAIL_NOT_VERIFIED_ERROR';
    public readonly message: string = 'Email Not Verified';
  }

  export class EmailAlreadyVerified implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'EMAIL_ALREADY_VERIFIED_ERROR';
    public readonly message: string = 'Email Already Verified';
  }

  export class InvalidVerificationToken
    implements Cumulonimbus.Structures.Error
  {
    public readonly code: string = 'INVALID_VERIFICATION_TOKEN_ERROR';
    public readonly message: string = 'Invalid Verification Token';
  }

  export class InvalidSession implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_SESSION_ERROR';
    public readonly message: string = 'Invalid Session';
  }

  export class InvalidDomain implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_DOMAIN_ERROR';
    public readonly message: string = 'Invalid Domain';
  }

  export class SubdomainTooLong implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'SUBDOMAIN_TOO_LONG_ERROR';
    public readonly message: string = 'Subdomain Too Long';
  }

  export class InvalidFile implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_FILE_ERROR';
    public readonly message: string = 'Invalid File';
  }

  export class InvalidInstruction implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_INSTRUCTION_ERROR';
    public readonly message: string = 'Invalid Instruction';
  }

  export class InvalidEndpoint implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INVALID_ENDPOINT_ERROR';
    public readonly message: string = 'Invalid Endpoint';
  }

  export class SubdomainNotAllowed implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'SUBDOMAIN_NOT_ALLOWED_ERROR';
    public readonly message: string = 'Subdomain Not Allowed';
  }

  export class DomainExists implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'DOMAIN_EXISTS_ERROR';
    public readonly message: string = 'Domain Exists';
  }

  export class UserExists implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'USER_EXISTS_ERROR';
    public readonly message: string = 'User Exists';
  }

  export class InstructionExists implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INSTRUCTION_EXISTS_ERROR';
    public readonly message: string = 'Instruction Exists';
  }

  export class MissingFields implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'MISSING_FIELDS_ERROR';
    public readonly message: string = 'Missing Fields';
    constructor(public readonly fields: string[]) {}
  }

  export class Banned implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'BANNED_ERROR';
    public readonly message: string = 'Banned';
  }

  export class BodyTooLarge implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'BODY_TOO_LARGE_ERROR';
    public readonly message: string = 'Body Too Large';
  }

  export class ServiceUnavailable implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'SERVICE_UNAVAILABLE_ERROR';
    public readonly message: string = 'Service Unavailable';
    constructor(public readonly feature: number) {}
  }

  export class RateLimited implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'RATELIMITED_ERROR';
    public readonly message: string =
      'You Have Been Ratelimited. Please Try Again Later.';
  }

  export class Internal implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'INTERNAL_SERVER_ERROR';
    public readonly message: string = 'Internal Server Error';
  }

  export class NotImplemented implements Cumulonimbus.Structures.Error {
    public readonly code: string = 'NOT_IMPLEMENTED_ERROR';
    public readonly message: string = 'Not Implemented';
  }
}

export namespace Success {
  export class DeleteUser implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_USER_SUCCESS';
    public readonly message: string = 'User Successfully Deleted';
  }

  export class DeleteUsers implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_USERS_SUCCESS';
    public readonly message: string = 'Users Successfully Deleted';
    constructor(public readonly count: number) {}
  }

  export class DeleteFile implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_FILE_SUCCESS';
    public readonly message: string = 'File Successfully Deleted';
  }

  export class DeleteFiles implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_FILES_SUCCESS';
    public readonly message: string = 'Files Successfully Deleted';
    constructor(public readonly count: number) {}
  }

  export class DeleteSession implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_SESSION_SUCCESS';
    public readonly message: string = 'Session Successfully Deleted';
  }

  export class DeleteSessions implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_SESSIONS_SUCCESS';
    public readonly message: string = 'Sessions Successfully Deleted';
    constructor(public readonly count: number) {}
  }

  export class DeleteDomain implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_DOMAIN_SUCCESS';
    public readonly message: string = 'Domain Successfully Deleted';
  }

  export class DeleteDomains implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_DOMAINS_SUCCESS';
    public readonly message: string = 'Domains Successfully Deleted';
    constructor(public readonly count: number) {}
  }

  export class DeleteInstruction implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_INSTRUCTION_SUCCESS';
    public readonly message: string = 'Instruction Successfully Deleted';
  }

  export class DeleteInstructions implements Cumulonimbus.Structures.Success {
    public readonly code: string = 'DELETE_INSTRUCTIONS_SUCCESS';
    public readonly message: string = 'Instructions Successfully Deleted';
    constructor(public readonly count: number) {}
  }

  export class SendVerificationEmail
    implements Cumulonimbus.Structures.Success
  {
    public readonly code: string = 'SEND_VERIFICATION_EMAIL_SUCCESS';
    public readonly message: string = 'Verification Email Successfully Sent';
  }
}
