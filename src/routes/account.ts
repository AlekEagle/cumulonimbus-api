import { logger, app } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import {
  USERNAME_REGEX,
  EMAIL_REGEX,
  PASSWORD_HASH_ROUNDS,
  OMITTED_USER_FIELDS,
} from '../utils/Constants.js';
import SubdomainFormatter from '../utils/SubdomainFormatter.js';
import AutoTrim from '../middleware/AutoTrim.js';
import Domain from '../DB/Domain.js';
import User from '../DB/User.js';
import File from '../DB/File.js';
import {
  generateSessionToken,
  nameSession,
  validateToken,
} from '../utils/Token.js';
import defaultRateLimitConfig from '../utils/RateLimitUtils.js';
import KVExtractor from '../utils/KVExtractor.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import LimitOffset from '../middleware/LimitOffset.js';
import sendVerificationEmail from '../mail/EmailVerification.js';
import { sendBannedNotice } from '../mail/BannedNotice.js';
import KillSwitch from '../middleware/KillSwitch.js';
import { KillSwitches } from '../utils/GlobalKillSwitches.js';
import ReverifyIdentity from '../middleware/ReverifyIdentity.js';
import Session from '../DB/Session.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';

import { Request, Response } from 'express';
import Bcrypt from 'bcrypt';
import { Op } from 'sequelize';
import ExpressRateLimit from 'express-rate-limit';
import { join } from 'node:path';
import { unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import ms from 'ms';

logger.debug('Loading: Account Routes...');

// TODO: add a way for users to undo unauthorized account changes

app.post(
  // POST /api/register
  '/api/register',
  KillSwitch(KillSwitches.ACCOUNT_CREATE),
  KillSwitch(KillSwitches.ACCOUNT_EMAIL_VERIFY),
  AutoTrim(['password', 'confirmPassword']),
  BodyValidator({
    username: 'string',
    email: 'string',
    password: 'string',
    confirmPassword: 'string',
    rememberMe: new ExtendedValidBodyTypes('boolean', true),
  }),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: ms('1h'), // 1 hour
    max: 1,
    // Skip responses that result in 409 Conflict (UserExists)
    // FIXME: This does NOT work, skip is processed before the response is sent.
    skip(_, res) {
      return res.statusCode === 409;
    },
  }),
  async (
    req: Request<
      null,
      null,
      {
        username: string;
        email: string;
        password: string;
        confirmPassword: string;
        rememberMe?: boolean;
      }
    >,
    res: Response<
      Cumulonimbus.Structures.SuccessfulAuth | Cumulonimbus.Structures.Error
    >,
  ) => {
    // If someone attempts to register while logged in, return an InvalidSession error.
    if (req.user) return res.status(401).json(new Errors.InvalidSession());

    // If the password and confirmPassword fields do not match, return a PasswordsDoNotMatch error.
    if (req.body.password !== req.body.confirmPassword)
      return res.status(400).json(new Errors.PasswordsDoNotMatch());

    // If the username or email do not match their respective RegExp, return an InvalidUsername or InvalidEmail error.
    if (!USERNAME_REGEX.test(req.body.username))
      return res.status(400).json(new Errors.InvalidUsername());

    if (!EMAIL_REGEX.test(req.body.email))
      return res.status(400).json(new Errors.InvalidEmail());

    // Check if the username or email are already in use.
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [
          { username: req.body.username.toLowerCase() },
          { email: req.body.email.toLowerCase() },
        ],
      },
    });

    // If a user with the same username or email exists, return UserExists error.
    if (existingUser) return res.status(409).json(new Errors.UserExists());

    try {
      // Get the current Unix timestamp.
      const now = Date.now().toString();

      // Hash the password.
      const hashedPassword = await Bcrypt.hash(
        req.body.password,
        PASSWORD_HASH_ROUNDS,
      );

      const tokenName = nameSession(req);

      // Generate a session token.
      const token = await generateSessionToken(now, req.body.rememberMe);

      // Send the verification email.
      const { success, error, tokenData } = await sendVerificationEmail(
        req.body.email,
        req.body.username,
      );

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }

      // Create the user.
      const user = await User.create({
        id: now,
        username: req.body.username,
        password: hashedPassword,
        email: req.body.email,
        domain: process.env.DEFAULT_DOMAIN,
        subdomain: null,
        verificationRequestedAt: tokenData.payload.iat,
      });

      // Create a corresponding session.
      await Session.create({
        name: tokenName,
        token: token.token,
        expiresAt: new Date(token.data.payload.exp * 1000),
      });

      logger.debug(`User ${user.username} (${user.id}) account created.`);
      // Send the user object
      return res
        .status(201)
        .json({ token: token.token, exp: token.data.payload.exp });
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users
  '/api/users',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ),
  LimitOffset(0, 50),
  async (
    req: Request<
      null,
      null,
      null,
      {
        limit?: string;
        offset?: string;
      }
    >,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.User>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the users.
      const { count, rows: users } = await User.findAndCountAll({
        limit: req.limit,
        offset: req.offset,
        order: [['createdAt', 'DESC']],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched users. (offset: ${req.offset}, limit: ${req.limit})`,
      );

      // Send the users.
      return res.status(200).json({
        count,
        items: users.map((user) =>
          KVExtractor(user.toJSON(), ['id', 'username']),
        ),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/me
  '/api/users/me',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.ACCOUNT_READ),
  async (
    req: Request,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    logger.debug(
      `User ${req.user.username} (${req.user.id}) fetched their own user object.`,
    );
    // Send the user object.
    return res
      .status(200)
      .json(KVExtractor(req.user.toJSON(), OMITTED_USER_FIELDS, true));
  },
);

app.get(
  // GET /api/users/:id
  '/api/users/:id([0-9]{13})',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched user ${user.username} (${user.id}).`,
      );

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/me/username
  '/api/users/me/username',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),

  AutoTrim(),
  BodyValidator({
    username: 'string',
  }),
  async (
    req: Request<null, null, { username: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Check if the username meets username character requirements
      if (!USERNAME_REGEX.test(req.body.username))
        return res.status(400).json(new Errors.InvalidUsername());

      // Check if the username is already taken.
      if (await User.findOne({ where: { username: req.body.username } }))
        return res.status(409).json(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their username to ${req.body.username}.`,
      );

      // Update the username.
      await req.user.update({ username: req.body.username });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(req.user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/username
  '/api/users/:id([0-9]{13})/username',
  ReverifyIdentity(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY),
  AutoTrim(),
  BodyValidator({
    username: 'string',
  }),
  async (
    req: Request<{ id: string }, null, { username: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the username meets username character requirements
      if (!USERNAME_REGEX.test(req.body.username))
        return res.status(400).json(new Errors.InvalidUsername());

      // Check if the username is already taken.
      if (await User.findOne({ where: { username: req.body.username } }))
        return res.status(409).json(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s username to ${req.body.username}.`,
      );

      // Update the username.
      await user.update({ username: req.body.username });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/me/email
  '/api/users/me/email',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  KillSwitch(KillSwitches.ACCOUNT_EMAIL_VERIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(PermissionFlags.ACCOUNT_MODIFY),
  AutoTrim(),
  BodyValidator({
    email: 'string',
  }),
  async (
    req: Request<null, null, { email: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Check if the email is a valid email
      if (!EMAIL_REGEX.test(req.body.email))
        return res.status(400).json(new Errors.InvalidEmail());

      // Check if the email is already taken.
      if (await User.findOne({ where: { email: req.body.email } }))
        return res.status(409).json(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their email to ${req.body.email}. (Previously: ${req.user.email})`,
      );

      const { success, error, tokenData } = await sendVerificationEmail(
        req.body.email,
        req.user.username,
      );

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }

      // Update the email.
      await req.user.update({
        email: req.body.email,
        verifiedAt: null,
        verificationRequestedAt: tokenData.payload.iat,
      });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(req.user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/email
  '/api/users/:id([0-9]{13})/email',
  ReverifyIdentity(true),
  SessionPermissionChecker(
    PermissionFlags.ACCOUNT_MODIFY | PermissionFlags.STAFF_MODIFY,
  ),
  AutoTrim(),
  BodyValidator({
    email: 'string',
    password: new ExtendedValidBodyTypes('string', true),
  }),
  async (
    req: Request<{ id: string }, null, { email: string; password?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the email is a valid email
      if (!EMAIL_REGEX.test(req.body.email))
        return res.status(400).json(new Errors.InvalidEmail());

      // Check if the email is already taken.
      if (await User.findOne({ where: { email: req.body.email } }))
        return res.status(409).json(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s email to ${req.body.email}. (Previously: ${user.email})`,
      );

      // Don't send a verification email, staff can verify emails without user interaction.
      // And if the staff wants to send an email, they can use the /api/users/:id/verify endpoint.

      // Update the email.
      await user.update({ email: req.body.email });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/verify
  '/api/users/verify',
  BodyValidator({
    token: 'string',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<null, null, { token: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      const result = await validateToken(req.body.token);

      if (result instanceof Error) {
        logger.error(result);
        return res.status(400).json(new Errors.InvalidVerificationToken());
      } else {
        // Find the user that we're verifying
        const user = await User.findOne({
          where: {
            email: result.payload.sub,
            verificationRequestedAt: new Date(result.payload.iat),
          },
        });
        // If there's no user, return an InvalidVerificationToken error
        if (!user)
          return res.status(400).json(new Errors.InvalidVerificationToken());

        // Update the user's email verification status.
        await user.update({
          verificationRequestedAt: null,
          verifiedAt: new Date(),
        });

        return res.status(200).json(new Success.VerifyEmail());
      }
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/verify
  '/api/users/:id([0-9]{13})/verify',
  ReverifyIdentity(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the user's email is already verified.
      if (user.verifiedAt)
        return res.status(400).json(new Errors.EmailAlreadyVerified());

      // Verify the user's email.
      await user.update({
        verifiedAt: new Date(),
        verificationRequestedAt: null,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) verified user ${user.username} (${user.id})'s email.`,
      );

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id/verify
  '/api/users/:id([0-9]{13})/verify',
  ReverifyIdentity(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the user's email is already unverified.
      if (!user.verifiedAt)
        return res.status(400).json(new Errors.EmailNotVerified());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) unverified user ${user.username} (${user.id})'s email.`,
      );

      // Update the user's email verification status.
      await user.update({ verifiedAt: null });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/me/verify
  '/api/users/me/verify',
  SessionChecker(),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: ms('5m'),
    max: 1,
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  KillSwitch(KillSwitches.ACCOUNT_EMAIL_VERIFY),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Check if the user's email is already verified.
      if (req.user.verifiedAt)
        return res.status(400).json(new Errors.EmailAlreadyVerified());

      // Send the verification email.
      const {
        success,
        error,
        token: verifyToken,
      } = await sendVerificationEmail(req.user.email, req.user.username);

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }

      // Update the user's email verification status.
      await req.user.update({
        verificationRequestedAt: new Date(),
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested a new verification email.`,
      );

      // Send a success response.
      return res.status(201).json(new Success.SendVerificationEmail());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:id/verify
  '/api/users/:id([0-9]{13})/verify',
  SessionChecker(true),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: ms('5m'),
    max: 1,
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the user's email is already verified.
      if (user.verifiedAt)
        return res.status(400).json(new Errors.EmailAlreadyVerified());

      // Send the verification email.
      const {
        success,
        error,
        token: verifyToken,
      } = await sendVerificationEmail(user.email, user.username);

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }

      // Update the user's email verification status.
      await user.update({
        verificationRequestedAt: new Date(),
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested a new verification email for user ${user.username} (${user.id}).`,
      );

      // Send a success response.
      return res.status(201).json(new Success.SendVerificationEmail());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/me/password
  '/api/users/me/password',
  ReverifyIdentity(),
  AutoTrim(),
  BodyValidator({
    newPassword: 'string',
    confirmNewPassword: 'string',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<
      null,
      null,
      { newPassword: string; confirmNewPassword: string }
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Check if the new password matches the confirmation.
      if (req.body.newPassword !== req.body.confirmNewPassword)
        return res.status(400).json(new Errors.PasswordsDoNotMatch());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their password.`,
      );

      // Update the password.
      await req.user.update({
        password: await Bcrypt.hash(req.body.newPassword, PASSWORD_HASH_ROUNDS),
      });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(req.user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/password
  '/api/users/:id([0-9]{13})/password',
  ReverifyIdentity(true),
  BodyValidator({
    newPassword: 'string',
    confirmNewPassword: 'string',
  }),
  async (
    req: Request<
      { id: string },
      null,
      { newPassword: string; confirmNewPassword: string }
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the new password matches the confirmation.
      if (req.body.newPassword !== req.body.confirmNewPassword)
        return res.status(400).json(new Errors.PasswordsDoNotMatch());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s password.`,
      );

      // Update the password.
      await user.update({
        password: await Bcrypt.hash(req.body.newPassword, PASSWORD_HASH_ROUNDS),
      });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/staff
  '/api/users/:id([0-9]{13})/staff',
  ReverifyIdentity(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) granted user ${user.username} (${user.id}) staff privileges.`,
      );

      // Update the staff status.
      await user.update({ staff: true });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id/staff
  '/api/users/:id([0-9]{13})/staff',
  ReverifyIdentity(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) revoked user ${user.username} (${user.id})'s staff privileges.`,
      );

      // Update the staff status.
      await user.update({ staff: false });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/ban
  '/api/users/:id([0-9]{13})/ban',
  ReverifyIdentity(true),
  BodyValidator({
    reason: 'string',
  }),
  async (
    req: Request<{ id: string }, null, { reason: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) banned user ${user.username} (${user.id}).`,
      );

      // Notify the user that they have been banned.
      const { success, error } = await sendBannedNotice(
        user.email,
        user.username,
        req.body.reason,
      );

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }

      // Update the banned status.
      await user.update({ bannedAt: new Date() });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id/ban
  '/api/users/:id([0-9]{13})/ban',
  ReverifyIdentity(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) unbanned user ${user.username} (${user.id}).`,
      );

      // Update the banned status.
      await user.update({ bannedAt: null });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/me/domain
  '/api/users/me/domain',
  SessionChecker(),
  AutoTrim(),
  BodyValidator({
    domain: 'string',
    subdomain: new ExtendedValidBodyTypes('string', true),
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<null, null, { domain: string; subdomain?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Check if the domain is valid.
      let domain = await Domain.findByPk(req.body.domain);
      if (!domain) return res.status(404).json(new Errors.InvalidDomain());

      // Check if the domain permits subdomains.
      if (!domain.subdomains && req.body.subdomain)
        return res.status(400).json(new Errors.SubdomainNotAllowed());

      // Format the subdomain to comply with URL standards.
      let subdomain = req.body.subdomain
        ? SubdomainFormatter(req.body.subdomain)
        : null;

      // Check if the subdomain exceeds the maximum length.
      if (subdomain && subdomain.length > 63)
        return res.status(400).json(new Errors.SubdomainTooLong());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their domain to ${domain.id} and subdomain to ${subdomain}.`,
      );

      // Update the user's domain and subdomain.
      await req.user.update({ domain: domain.id, subdomain });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(req.user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/domain
  '/api/users/:id([0-9]{13})/domain',
  SessionChecker(true),
  AutoTrim(),
  BodyValidator({
    domain: 'string',
    subdomain: new ExtendedValidBodyTypes('string', true),
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<{ id: string }, null, { domain: string; subdomain?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Check if the domain is valid.
      let domain = await Domain.findByPk(req.body.domain);
      if (!domain) return res.status(404).json(new Errors.InvalidDomain());

      // Check if the domain permits subdomains.
      if (!domain.subdomains && req.body.subdomain)
        return res.status(400).json(new Errors.SubdomainNotAllowed());

      // Format the subdomain to comply with URL standards.
      let subdomain = req.body.subdomain
        ? SubdomainFormatter(req.body.subdomain)
        : null;

      // Check if the subdomain exceeds the maximum length.
      if (subdomain && subdomain.length > 63)
        return res.status(400).json(new Errors.SubdomainTooLong());

      // Update the user's domain and subdomain.
      await user.update({ domain: domain.id, subdomain });

      // Send the user object.
      return res
        .status(200)
        .json(KVExtractor(user.toJSON(), OMITTED_USER_FIELDS, true));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me
  '/api/users/me',
  ReverifyIdentity(),
  KillSwitch(KillSwitches.ACCOUNT_DELETE),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Delete the user's files.
      const files = await File.findAll({ where: { userID: req.user.id } });

      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      // Delete the user.
      await req.user.destroy();

      return res.status(200).json(new Success.DeleteUser());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id
  '/api/users/:id([0-9]{13})',
  ReverifyIdentity(true),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Delete the user's files.
      const files = await File.findAll({ where: { userID: user.id } });

      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      // Delete the user.
      await user.destroy();

      return res.status(200).json(new Success.DeleteUser());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users
  '/api/users',
  ReverifyIdentity(true),
  AutoTrim(),
  BodyValidator({
    ids: new ExtendedValidBodyTypes('array', false, 'string'),
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Check if they're attempting to delete more than 50 users
      if (req.body.ids.length > 50)
        return res.status(400).json(new Errors.BodyTooLarge());

      // Get the users.
      const { count, rows: users } = await User.findAndCountAll({
        where: { id: { [Op.in]: req.body.ids } },
      });

      // If there are no users, return a InvalidUser error.
      if (!count) return res.status(404).json(new Errors.InvalidUser());

      // Delete the users.
      await Promise.all(
        users.map(async (user) => {
          // Delete the user's files.
          const files = await File.findAll({ where: { userID: user.id } });

          await Promise.all(
            files.map(async (file) => {
              // First, delete the thumbnail if it exists.
              if (
                existsSync(
                  join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
                )
              )
                await unlink(
                  join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
                );

              // Delete the file from the disk.
              await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

              // Delete the file from the database.
              await file.destroy();
            }),
          );

          // Delete the user.
          await user.destroy();
        }),
      );

      return res.status(200).json(new Success.DeleteUsers(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
