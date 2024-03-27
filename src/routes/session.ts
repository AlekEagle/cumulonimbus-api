import { logger, app } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import User from '../DB/User.js';
import AutoTrim from '../middleware/AutoTrim.js';
import defaultRateLimitConfig from '../utils/RateLimitUtils.js';
import {
  extractToken,
  generateSessionToken,
  nameSession,
} from '../utils/Token.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import LimitOffset from '../middleware/LimitOffset.js';
import KillSwitch from '../middleware/KillSwitch.js';
import { KillSwitches } from '../utils/GlobalKillSwitches.js';
import {
  generateSecondFactorChallenge,
  SecondFactorChallengeResponse,
  verifySecondFactor,
} from '../utils/SecondFactor.js';
import SecondFactor from '../DB/SecondFactor.js';

import { Request, Response } from 'express';
import Bcrypt from 'bcrypt';
import { fn, col, where } from 'sequelize';
import ExpressRateLimit from 'express-rate-limit';
import isType from '../utils/TypeAsserter.js';

logger.debug('Loading: Session Routes...');

app.post(
  // POST /api/login
  '/api/login',
  AutoTrim(),
  BodyValidator({
    username: new ExtendedValidBodyTypes('string', true),
    password: new ExtendedValidBodyTypes('string', true),
    rememberMe: new ExtendedValidBodyTypes('boolean', true),
    token: new ExtendedValidBodyTypes('string', true),
    type: new ExtendedValidBodyTypes('string', true),
    code: new ExtendedValidBodyTypes('string', true),
  }),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: 60 * 1000, // 1 minute
    max: 3,
  }),
  KillSwitch(KillSwitches.ACCOUNT_LOGIN),
  async (
    req: Request<
      null,
      null,
      | {
          username: string;
          password: string;
          rememberMe?: boolean;
        }
      | (SecondFactorChallengeResponse & { rememberMe?: boolean })
    >,
    res: Response<
      | Cumulonimbus.Structures.SuccessfulAuth
      | Cumulonimbus.Structures.SecondFactorChallenge
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // If the user is already logged in, return an InvalidSession error.
    if (req.user) return res.status(401).json(new Errors.InvalidSession());
    if (
      isType<{ username: string; password: string; rememberMe?: boolean }>(
        req.body,
        ['username'],
      )
    ) {
      try {
        // Find a user with the given username.
        let user = await User.findOne({
          where: where(
            fn('lower', col('username')),
            req.body.username.toLowerCase(),
          ),
        });

        // If no user was found, return an InvalidUser error.
        if (!user) return res.status(404).json(new Errors.InvalidUser());

        // If the user is banned, return a Banned error.
        if (user.bannedAt) return res.status(403).json(new Errors.Banned());

        // Compare the given password with the user's password.
        if (!(await Bcrypt.compare(req.body.password, user.password)))
          return res.status(401).json(new Errors.InvalidPassword());

        if (
          (await SecondFactor.findAll({ where: { user: user.id } })).length !==
          0
        ) {
          // If the user has second factors, generate a second factor challenge.
          return res
            .status(401)
            .json(await generateSecondFactorChallenge(user));
        }

        // Generate a session name for the new session.
        let sessionName =
          (req.headers['x-session-name'] as string) || nameSession(req);

        // Generate a new token for the user.
        let token = await generateSessionToken(user.id, req.body.rememberMe);

        // Add the new session to the user's sessions.
        let sessions = [
          ...user.sessions,
          {
            name: sessionName,
            iat: token.data.payload.iat,
            exp: token.data.payload.exp,
          },
        ];

        // Update the user's sessions.
        await user.update({ sessions });

        logger.debug(`User ${user.username} (${user.id}) logged in.`);

        // Return a SuccessfulAuth response.
        return res.status(201).json({
          token: token.token,
          exp: token.data.payload.exp,
        });
      } catch (error) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }
    } else {
      try {
        const uid = extractToken(req.body.token).payload.sub,
          user = await User.findByPk(uid);
        if (await verifySecondFactor(req.body, user, res)) {
          // Generate a session name for the new session.
          let sessionName =
            (req.headers['x-session-name'] as string) || nameSession(req);

          // Generate a new token for the user.
          let token = await generateSessionToken(user.id, req.body.rememberMe);

          // Add the new session to the user's sessions.
          let sessions = [
            ...user.sessions,
            {
              name: sessionName,
              iat: token.data.payload.iat,
              exp: token.data.payload.exp,
            },
          ];

          // Update the user's sessions.
          await user.update({ sessions });

          logger.debug(
            `User ${user.username} (${user.id}) logged in after solving 2FA challenge.`,
          );

          // Return a SuccessfulAuth response.
          return res.status(201).json({
            token: token.token,
            exp: token.data.payload.exp,
          });
        }
        // verifySecondFactor will handle sending the error response, we're done here.
        else return;
      } catch (error) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }
    }
  },
);

app.get(
  // GET /api/users/:uid/sessions/:sid
  '/api/users/:uid([0-9]{13}|me)/sessions/:sid([0-9]{10}|me)',
  SessionChecker(),
  async (
    req: Request<{ uid: string; sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user is requesting a session that belongs to them.
    if (req.params.uid === 'me') {
      // Check if the user is requesting the current session.
      if (req.params.sid === 'me') {
        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested their current session.`,
        );

        // Get the current session.
        let session = req.user.sessions.find(
          (session) => session.iat === req.session.payload.iat,
        );

        return res.status(200).json({
          id: session.iat,
          exp: session.exp,
          name: session.name,
        });
      }

      // Find the session with the given ID.
      let session = req.user.sessions.find(
        (session) => session.iat === parseInt(req.params.sid),
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested their session ${session.name} (${session.iat}).`,
      );

      // Return the session.
      return res.status(200).json({
        id: session.iat,
        exp: session.exp,
        name: session.name,
      });
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).json(new Errors.InsufficientPermissions());

    try {
      // Find the user with the given ID.
      let user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Find the session with the given ID.
      let session = user.sessions.find(
        (session) => session.iat === parseInt(req.params.sid),
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested user ${user.username} (${user.id})'s session ${session.name} (${session.iat}).`,
      );

      // Return the session.
      return res.status(200).json({
        id: session.iat,
        exp: session.exp,
        name: session.name,
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:uid/sessions
  '/api/users/:uid([0-9]{13}|me)/sessions',
  SessionChecker(),
  LimitOffset(0, 50),
  async (
    req: Request<{ uid: string }, null, null>,
    res: Response<
      | Cumulonimbus.Structures.List<{ id: number; name: string }>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user is requesting sessions that belong to them.
    if (req.params.uid === 'me') {
      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested their sessions.`,
      );

      // Return the user's sessions.
      return res.status(200).json({
        count: req.user.sessions.length,
        items: req.user.sessions
          .slice(req.offset, req.offset + req.limit)
          .map((session) => ({
            id: session.iat,
            name: session.name,
          }))
          .reverse(),
      });
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).json(new Errors.InsufficientPermissions());

    try {
      // Find the user with the given ID.
      let user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested user ${user.username} (${user.id})'s sessions.`,
      );

      // Return the user's sessions.
      return res.status(200).json({
        count: user.sessions.length,
        items: user.sessions
          .slice(req.offset, req.offset + req.limit)
          .map((session) => ({
            id: session.iat,
            name: session.name,
          })),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/sessions/:sid
  '/api/users/:uid([0-9]{13}|me)/sessions/:sid([0-9]{10}|me)',
  SessionChecker(),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<{ uid: string; sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user is requesting a session that belongs to them.
    if (req.params.uid === 'me') {
      // Check if the user is requesting the current session.
      if (req.params.sid === 'me') {
        // Remove the current session.
        let sessions = req.user.sessions.filter(
          (session) => session.iat !== req.session.payload.iat,
        );

        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested to remove their current session.`,
        );

        // Update the user's sessions.
        await req.user.update({ sessions });

        // Return a success.
        return res.status(200).json(new Success.DeleteSession());
      }

      // Find the session with the given ID.
      let session = req.user.sessions.find(
        (session) => session.iat === parseInt(req.params.sid),
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      // Remove the session.
      let sessions = req.user.sessions.filter(
        (session) => session.iat !== parseInt(req.params.sid),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove their session ${session.name} (${session.iat}).`,
      );

      // Update the user's sessions.
      await req.user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSession());
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).json(new Errors.InsufficientPermissions());

    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Find the session with the given ID.
      let session = user.sessions.find(
        (session) => session.iat === parseInt(req.params.sid),
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      // Remove the session.
      let sessions = user.sessions.filter(
        (session) => session.iat !== parseInt(req.params.sid),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove user ${user.username} (${user.id})'s session ${session.name} (${session.iat}).`,
      );

      // Update the user's sessions.
      await user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSession());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/sessions
  '/api/users/:uid([0-9]{13}|me)/sessions',
  SessionChecker(),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<{ uid: string }, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if they are trying to remove more than 50 sessions.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    // Check if the user is requesting sessions that belong to them.
    if (req.params.uid === 'me') {
      // Check if the user is requesting the current session.
      if (req.body.ids.includes('me'))
        // Replace `me` with the current session ID.
        req.body.ids[req.body.ids.indexOf('me')] =
          req.session.payload.iat.toString();

      // Remove the sessions.
      let sessions = req.user.sessions.filter(
        (session) => !req.body.ids.includes(session.iat.toString()),
      );

      // Count the number of sessions removed.
      let count = req.user.sessions.length - sessions.length;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove ${count} of their sessions.`,
      );

      // Update the user's sessions.
      await req.user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).json(new Errors.InsufficientPermissions());

    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Remove the sessions.
      let sessions = user.sessions.filter(
        (session) => !req.body.ids.includes(session.iat.toString()),
      );

      // Count the number of sessions removed.
      let count = user.sessions.length - sessions.length;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove ${count} of user ${user.username} (${user.id})'s sessions.`,
      );

      // Update the user's sessions.
      await user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/sessions/all
  '/api/users/:uid([0-9]{13}|me)/sessions/all',
  SessionChecker(),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<{ uid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user is requesting sessions that belong to them.
    if (req.params.uid === 'me') {
      // Remove the sessions.
      let sessions = req.query['include-self']
        ? []
        : req.user.sessions.filter(
            (session) => session.iat === req.session.payload.iat,
          );

      // Count the number of sessions removed.
      let count = req.user.sessions.length - sessions.length;

      logger.debug(
        `User ${req.user.username} (${
          req.user.id
        }) requested to remove all of their sessions. (they did${
          req.query['include-self'] ? '' : ' not'
        } include the current session)`,
      );

      // Update the user's sessions.
      await req.user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).json(new Errors.InsufficientPermissions());

    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Count the number of sessions removed.
      let count = user.sessions.length;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove all of user ${user.username} (${user.id})'s sessions.`,
      );

      // Update the user's sessions.
      await user.update({ sessions: [] });

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
