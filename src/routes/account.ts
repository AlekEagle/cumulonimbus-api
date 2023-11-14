import { logger, app } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import {
  USERNAME_REGEX,
  EMAIL_REGEX,
  PASSWORD_HASH_ROUNDS,
  EMAIL_VERIFICATION_TOKEN_EXPIRY,
} from '../utils/Constants.js';
import SubdomainFormatter from '../utils/SubdomainFormatter.js';
import AutoTrim from '../middleware/AutoTrim.js';
import Domain from '../DB/Domain.js';
import User from '../DB/User.js';
import File from '../DB/File.js';
import { generateToken, nameSession } from '../utils/Token.js';
import defaultRateLimitConfig from '../utils/RateLimitUtils.js';
import KVExtractor from '../utils/KVExtractor.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import LimitOffset from '../middleware/LimitOffset.js';
import { sendSignupVerificationEmail } from '../mail/SignupVerification.js';
import { sendResendVerificationEmail } from '../mail/ResendVerification.js';
import { sendUpdateVerificationEmail } from '../mail/UpdateVerification.js';

import { Request, Response } from 'express';
import Bcrypt from 'bcrypt';
import { Op } from 'sequelize';
import ExpressRateLimit from 'express-rate-limit';
import { join } from 'node:path';
import { unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import ms from 'ms';

logger.debug('Loading: Account Routes...');

app.post(
  // POST /api/register
  '/api/register',
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
    if (req.user) return res.status(401).send(new Errors.InvalidSession());

    // If the password and confirmPassword fields do not match, return a PasswordsDoNotMatch error.
    if (req.body.password !== req.body.confirmPassword)
      return res.status(400).send(new Errors.PasswordsDoNotMatch());

    // If the username or email do not match their respective RegExp, return an InvalidUsername or InvalidEmail error.
    if (!USERNAME_REGEX.test(req.body.username))
      return res.status(400).send(new Errors.InvalidUsername());

    if (!EMAIL_REGEX.test(req.body.email))
      return res.status(400).send(new Errors.InvalidEmail());

    // Check if the username or email are already in use.
    const existingUser = await User.findOne({
      where: {
        [Op.or]: [
          { username: req.body.username.toLowerCase() },
          { email: req.body.email },
        ],
      },
    });

    // If a user with the same username or email exists, return UserExists error.
    if (existingUser) return res.status(409).send(new Errors.UserExists());

    try {
      // Get the current Unix timestamp.
      const now = Date.now().toString();

      // Hash the password.
      const hashedPassword = await Bcrypt.hash(req.body.password, 15);

      const tokenName = nameSession(req);

      // Generate a session token.
      const token = await generateToken(now, req.body.rememberMe);

      // Send the verification email.
      const {
        success,
        error,
        token: verifyToken,
      } = await sendSignupVerificationEmail(req.body.email, req.body.username);

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }

      // Create the user and send the user object.
      const user = await User.create({
        id: now,
        username: req.body.username,
        password: hashedPassword,
        email: req.body.email,
        domain: process.env.DEFAULT_DOMAIN,
        subdomain: null,
        sessions: [
          {
            iat: token.data.payload.iat,
            exp: token.data.payload.exp,
            name: tokenName,
          },
        ],
        emailVerificationToken: verifyToken,
        verificationRequestedAt: new Date(),
      });
      logger.debug(`User ${user.username} (${user.id}) account created.`);
      return res
        .status(201)
        .send({ token: token.token, exp: token.data.payload.exp });
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users
  '/api/users',
  SessionChecker(true),
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
      return res.status(200).send({
        count,
        items: users.map((user) =>
          KVExtractor(user.toJSON(), ['id', 'username']),
        ),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:id
  '/api/users/:id([0-9]{13}|me)',
  SessionChecker(),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    // Check if the user is requesting their own user object.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched their own user object.`,
      );
      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            req.user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    }

    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched user ${user.username} (${user.id}).`,
      );

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/username
  '/api/users/:id([0-9]{13}|me)/username',
  SessionChecker(),
  AutoTrim(['password']),
  BodyValidator({
    username: 'string',
    password: new ExtendedValidBodyTypes('string', true),
  }),
  async (
    req: Request<{ id: string }, null, { username: string; password?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    // Check if the user wants to modify their own username.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      try {
        // This portion of the endpoint requires a password, if the password is not present, return an error 400
        if (!req.body.password)
          return res.status(400).json(new Errors.MissingFields(['password']));

        // Check if the username meets username character requirements
        if (!USERNAME_REGEX.test(req.body.username))
          return res.status(400).json(new Errors.InvalidUsername());

        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Check if the username is already taken.
        if (await User.findOne({ where: { username: req.body.username } }))
          return res.status(409).send(new Errors.UserExists());

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their username to ${req.body.username}.`,
        );

        // Update the username.
        await req.user.update({ username: req.body.username });

        // Send the user object.
        return res
          .status(200)
          .send(
            KVExtractor(
              req.user.toJSON(),
              [
                'password',
                'sessions',
                'emailVerificationToken',
                'verificationRequestedAt',
              ],
              true,
            ),
          );
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }

    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check if the username meets username character requirements
      if (!USERNAME_REGEX.test(req.body.username))
        return res.status(400).json(new Errors.InvalidUsername());

      // Check if the username is already taken.
      if (await User.findOne({ where: { username: req.body.username } }))
        return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s username to ${req.body.username}.`,
      );

      // Update the username.
      await user.update({ username: req.body.username });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/email
  '/api/users/:id([0-9]{13}|me)/email',
  SessionChecker(),
  AutoTrim(['password']),
  BodyValidator({
    email: 'string',
    password: new ExtendedValidBodyTypes('string', true),
  }),
  async (
    req: Request<{ id: string }, null, { email: string; password?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    // Check if the user wants to modify their own email.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      try {
        // This portion of the endpoint requires a password, if the password is not present, return an error 400
        if (!req.body.password)
          return res.status(400).json(new Errors.MissingFields(['password']));

        // Check if the email is a valid email
        if (!EMAIL_REGEX.test(req.body.email))
          return res.status(400).json(new Errors.InvalidEmail());

        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Check if the email is already taken.
        if (await User.findOne({ where: { email: req.body.email } }))
          return res.status(409).send(new Errors.UserExists());

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their email to ${req.body.email}. (Previously: ${req.user.email})`,
        );

        const {
          success,
          error,
          token: verifyToken,
        } = await sendUpdateVerificationEmail(
          req.body.email,
          req.user.username,
        );

        // If the email failed to send, return an error 500.
        if (!success) {
          logger.error(error);
          return res.status(500).send(new Errors.Internal());
        }

        // Update the email.
        await req.user.update({
          email: req.body.email,
          verified: false,
          emailVerificationToken: verifyToken,
          verificationRequestedAt: new Date(),
        });

        // Send the user object.
        return res
          .status(200)
          .send(
            KVExtractor(
              req.user.toJSON(),
              [
                'password',
                'sessions',
                'emailVerificationToken',
                'verificationRequestedAt',
              ],
              true,
            ),
          );
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }

    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check if the email is a valid email
      if (!EMAIL_REGEX.test(req.body.email))
        return res.status(400).json(new Errors.InvalidEmail());

      // Check if the email is already taken.
      if (await User.findOne({ where: { email: req.body.email } }))
        return res.status(409).send(new Errors.UserExists());

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
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/verify
  '/api/users/:id([0-9]{13}|me)/verify',
  SessionChecker(),
  BodyValidator({
    token: new ExtendedValidBodyTypes('string', true),
  }),
  async (
    req: Request<{ id: string }, null, { token?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    // Check if the user wants to verify their own email.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      // Check if the user's email is already verified.
      if (req.user.verified)
        return res.status(400).send(new Errors.EmailAlreadyVerified());

      // Check if the user has a verification token.
      if (!req.user.emailVerificationToken)
        return res.status(400).send(new Errors.InvalidVerificationToken());

      // Check if the verification token has expired.
      if (
        Date.now() - req.user.verificationRequestedAt.getTime() >
        ms(EMAIL_VERIFICATION_TOKEN_EXPIRY)
      )
        return res.status(400).send(new Errors.InvalidVerificationToken());

      // Check if the token matches the user's verification token.
      if (req.body.token !== req.user.emailVerificationToken)
        return res.status(400).send(new Errors.InvalidVerificationToken());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) verified their email.`,
      );

      // Update the user's email verification status.
      await req.user.update({
        verified: true,
        emailVerificationToken: null,
        verificationRequestedAt: null,
      });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            req.user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } else {
      // If the user is not staff, return a InsufficientPermissions error.
      if (!req.user.staff)
        return res.status(403).send(new Errors.InsufficientPermissions());

      try {
        // Get the user.
        const user = await User.findByPk(req.params.id);

        // If the user does not exist, return a InvalidUser error.
        if (!user) return res.status(404).send(new Errors.InvalidUser());

        // Check if the user's email is already verified.
        if (user.verified)
          return res.status(400).send(new Errors.EmailAlreadyVerified());

        // Verify the user's email.
        await user.update({
          verified: true,
          emailVerificationToken: null,
          verificationRequestedAt: null,
        });

        logger.debug(
          `User ${req.user.username} (${req.user.id}) verified user ${user.username} (${user.id})'s email.`,
        );

        // Send the user object.
        return res
          .status(200)
          .send(
            KVExtractor(
              user.toJSON(),
              [
                'password',
                'sessions',
                'emailVerificationToken',
                'verificationRequestedAt',
              ],
              true,
            ),
          );
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }
  },
);

app.delete(
  // DELETE /api/users/:id/verify
  '/api/users/:id([0-9]{13})/verify',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check if the user's email is already unverified.
      if (!user.verified)
        return res.status(400).send(new Errors.EmailNotVerified());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) unverified user ${user.username} (${user.id})'s email.`,
      );

      // Update the user's email verification status.
      await user.update({ verified: false });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:id/verify
  '/api/users/:id([0-9]{13}|me)/verify',
  SessionChecker(),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: ms('5m'),
    max: 1,
  }),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user wants to request a new verification email for their own account.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      // Check if the user's email is already verified.
      if (req.user.verified)
        return res.status(400).send(new Errors.EmailAlreadyVerified());

      // Send the verification email.
      const {
        success,
        error,
        token: verifyToken,
      } = await sendResendVerificationEmail(req.user.email, req.user.username); // TODO: Create a separate email type for this

      // If the email failed to send, return an error 500.
      if (!success) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }

      // Update the user's email verification status.
      await req.user.update({
        emailVerificationToken: verifyToken,
        verificationRequestedAt: new Date(),
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested a new verification email.`,
      );

      // Send a success response.
      return res.status(201).json(new Success.SendVerificationEmail());
    } else {
      // If the user is not staff, return a InsufficientPermissions error.
      if (!req.user.staff)
        return res.status(403).send(new Errors.InsufficientPermissions());

      try {
        // Get the user.
        const user = await User.findByPk(req.params.id);

        // If the user does not exist, return a InvalidUser error.
        if (!user) return res.status(404).send(new Errors.InvalidUser());

        // Check if the user's email is already verified.
        if (user.verified)
          return res.status(400).send(new Errors.EmailAlreadyVerified());

        // Send the verification email.
        const {
          success,
          error,
          token: verifyToken,
        } = await sendResendVerificationEmail(user.email, user.username); // TODO: Create a separate email type for this

        // If the email failed to send, return an error 500.
        if (!success) {
          logger.error(error);
          return res.status(500).send(new Errors.Internal());
        }

        // Update the user's email verification status.
        await user.update({
          emailVerificationToken: verifyToken,
          verificationRequestedAt: new Date(),
        });

        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested a new verification email for user ${user.username} (${user.id}).`,
        );

        // Send a success response.
        return res.status(201).json(new Success.SendVerificationEmail());
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }
  },
);

app.put(
  // PUT /api/users/:id/password
  '/api/users/:id([0-9]{13}|me)/password',
  SessionChecker(),
  BodyValidator({
    password: new ExtendedValidBodyTypes('string', true),
    newPassword: 'string',
    confirmNewPassword: 'string',
  }),
  async (
    req: Request<
      { id: string },
      null,
      { password?: string; newPassword: string; confirmNewPassword: string }
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    // Check if the user wants to modify their own password.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      try {
        // This portion of the endpoint requires a password, if the password is not present, return an error 400
        if (!req.body.password)
          return res.status(400).json(new Errors.MissingFields(['password']));

        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Check if the new password matches the confirmation.
        if (req.body.newPassword !== req.body.confirmNewPassword)
          return res.status(400).send(new Errors.PasswordsDoNotMatch());

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their password.`,
        );

        // Update the password.
        await req.user.update({
          password: await Bcrypt.hash(
            req.body.newPassword,
            PASSWORD_HASH_ROUNDS,
          ),
        });

        // Send the user object.
        return res
          .status(200)
          .send(
            KVExtractor(
              req.user.toJSON(),
              [
                'password',
                'sessions',
                'emailVerificationToken',
                'verificationRequestedAt',
              ],
              true,
            ),
          );
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }

    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check if the new password matches the confirmation.
      if (req.body.newPassword !== req.body.confirmNewPassword)
        return res.status(400).send(new Errors.PasswordsDoNotMatch());

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
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/staff
  '/api/users/:id([0-9]{13})/staff',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) granted user ${user.username} (${user.id}) staff privileges.`,
      );

      // Update the staff status.
      await user.update({ staff: true });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id/staff
  '/api/users/:id([0-9]{13})/staff',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) revoked user ${user.username} (${user.id})'s staff privileges.`,
      );

      // Update the staff status.
      await user.update({ staff: false });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/ban
  '/api/users/:id([0-9]{13})/ban',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) banned user ${user.username} (${user.id}).`,
      );

      // Update the banned status.
      await user.update({ bannedAt: new Date() });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id/ban
  '/api/users/:id([0-9]{13})/ban',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) unbanned user ${user.username} (${user.id}).`,
      );

      // Update the banned status.
      await user.update({ bannedAt: null });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:id/domain
  '/api/users/:id([0-9]{13}|me)/domain',
  SessionChecker(),
  AutoTrim(),
  BodyValidator({
    domain: 'string',
    subdomain: new ExtendedValidBodyTypes('string', true),
  }),
  async (
    req: Request<{ id: string }, null, { domain: string; subdomain?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>,
  ) => {
    // Check if the user is trying to change their own domain.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      try {
        // Check if the domain is valid.
        let domain = await Domain.findByPk(req.body.domain);
        if (!domain) return res.status(404).send(new Errors.InvalidDomain());

        // Check if the domain permits subdomains.
        if (!domain.subdomains && req.body.subdomain)
          return res.status(400).send(new Errors.SubdomainNotAllowed());

        // Format the subdomain to comply with URL standards.
        let subdomain = req.body.subdomain
          ? SubdomainFormatter(req.body.subdomain)
          : null;

        // Check if the subdomain exceeds the maximum length.
        if (subdomain && subdomain.length > 63)
          return res.status(400).send(new Errors.SubdomainTooLong());

        // Update the user's domain and subdomain.
        await req.user.update({ domain: domain.id, subdomain });

        // Send the user object.
        return res
          .status(200)
          .send(
            KVExtractor(
              req.user.toJSON(),
              [
                'password',
                'sessions',
                'emailVerificationToken',
                'verificationRequestedAt',
              ],
              true,
            ),
          );
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }

    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check if the domain is valid.
      let domain = await Domain.findByPk(req.body.domain);
      if (!domain) return res.status(404).send(new Errors.InvalidDomain());

      // Check if the domain permits subdomains.
      if (!domain.subdomains && req.body.subdomain)
        return res.status(400).send(new Errors.SubdomainNotAllowed());

      // Format the subdomain to comply with URL standards.
      let subdomain = req.body.subdomain
        ? SubdomainFormatter(req.body.subdomain)
        : null;

      // Check if the subdomain exceeds the maximum length.
      if (subdomain && subdomain.length > 63)
        return res.status(400).send(new Errors.SubdomainTooLong());

      // Update the user's domain and subdomain.
      await user.update({ domain: domain.id, subdomain });

      // Send the user object.
      return res
        .status(200)
        .send(
          KVExtractor(
            user.toJSON(),
            [
              'password',
              'sessions',
              'emailVerificationToken',
              'verificationRequestedAt',
            ],
            true,
          ),
        );
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:id
  '/api/users/:id([0-9]{13}|me)',
  SessionChecker(),
  AutoTrim(['password']),
  BodyValidator({
    username: new ExtendedValidBodyTypes('string', true),
    password: new ExtendedValidBodyTypes('string', true),
  }),
  async (
    req: Request<
      { id: string },
      null,
      { username?: string; password?: string }
    >,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user is trying to delete their own account.
    if (req.params.id === 'me' || req.params.id === req.user.id) {
      try {
        // This portion of the endpoint requires both the username and password, if not present, return an error 400
        if (!req.body.username || !req.body.password)
          return res
            .status(400)
            .json(
              new Errors.MissingFields(
                [
                  !req.body.username ? 'username' : undefined,
                  !req.body.password ? 'password' : undefined,
                ].filter((v) => v !== undefined),
              ),
            );

        // Check if the username in the body matches the user's username.
        if (req.body.username !== req.user.username)
          return res.status(400).send(new Errors.InvalidUsername());

        // Check if the password in the body matches the user's password.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(400).send(new Errors.InvalidPassword());

        // Delete the user's files.
        const files = await File.findAll({ where: { userID: req.user.id } });

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
        await req.user.destroy();

        return res.status(200).send(new Success.DeleteUser());
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }

    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

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

      return res.status(200).send(new Success.DeleteUser());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users
  '/api/users',
  SessionChecker(true),
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
        return res.status(400).json(new Errors.MissingFields(['ids'])); //TODO: Propose a "SelectionTooLarge" error

      // Get the users.
      const { count, rows: users } = await User.findAndCountAll({
        where: { id: { [Op.in]: req.body.ids } },
      });

      // If there are no users, return a InvalidUser error.
      if (!count) return res.status(404).send(new Errors.InvalidUser());

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

      return res.status(200).send(new Success.DeleteUsers(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  },
);
