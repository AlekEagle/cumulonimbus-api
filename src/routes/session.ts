import { logger, app, ratelimitStore } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import User from '../DB/User.js';
import AutoTrim from '../middleware/AutoTrim.js';
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
import Ratelimit from '../middleware/Ratelimit.js';
import SecondFactor from '../DB/SecondFactor.js';
import Session from '../DB/Session.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';
import ReverifyIdentity from '../middleware/ReverifyIdentity.js';
import KVExtractor from '../utils/KVExtractor.js';

import { Request, Response } from 'express';
import Bcrypt from 'bcrypt';
import { fn, col, where, Op } from 'sequelize';
import ms from 'ms';

logger.debug('Loading: Session Routes...');

app.post(
  // POST /api/login
  '/api/login',
  KillSwitch(KillSwitches.ACCOUNT_LOGIN),
  AutoTrim(),
  BodyValidator({
    username: new ExtendedValidBodyTypes().string().notRequired(),
    password: new ExtendedValidBodyTypes().string().notRequired(),
    rememberMe: new ExtendedValidBodyTypes().boolean().notRequired(),
    token: new ExtendedValidBodyTypes().string().notRequired(),
    type: new ExtendedValidBodyTypes().string().notRequired(),
    code: new ExtendedValidBodyTypes().string().notRequired(),
    response: new ExtendedValidBodyTypes().any().notRequired(),
  }),
  Ratelimit({
    max: 4,
    window: ms('5m'),
    ignoreStatusCodes: [404],
    storage: ratelimitStore,
  }),
  async (
    req: Request<
      {},
      {},
      | {
          username: string;
          password: string;
          rememberMe?: boolean;
        }
      | {
          '2fa': SecondFactorChallengeResponse;
          'rememberMe'?: boolean;
        }
    >,
    res: Response<
      | Cumulonimbus.Structures.SuccessfulAuth
      | Cumulonimbus.Structures.SecondFactorChallenge
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // If the user is already logged in, return an InvalidSession error.
    if (req.user) return res.status(401).json(new Errors.InvalidSession());
    if ('password' in req.body) {
      try {
        // Find a user with the given username.
        const user = await User.findOne({
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
          return res.status(404).json(new Errors.InvalidUser()); // Return InvalidUser if the password is incorrect to prevent user enumeration.

        if (
          (await SecondFactor.findAll({ where: { user: user.id } })).length !==
          0
        ) {
          // If the user has second factors, generate a second factor challenge.
          // Skip the ratelimit for this request to prevent the user from being ratelimited for their second factor.
          res.ratelimit!.skipped = true;
          return res
            .status(401)
            .json(await generateSecondFactorChallenge(user));
        }

        // Generate a session name for the new session.
        const sessionName =
          (req.headers['x-session-name'] as string) || nameSession(req);

        // Generate a new token for the user.
        const token = await generateSessionToken(user.id, req.body.rememberMe);

        // Create a new session for the user.
        await Session.create({
          id: token.data.payload.iat.toString(),
          user: user.id,
          exp: new Date(token.data.payload.exp * 1000),
          name: sessionName,
        });

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
        const uid = extractToken(req.body['2fa'].token).payload.sub,
          user = await User.findByPk(uid);
        if (!user) return res.status(404).json(new Errors.InvalidUser());
        if (await verifySecondFactor(req.body['2fa'], user, res)) {
          // Generate a session name for the new session.
          const sessionName =
            (req.headers['x-session-name'] as string) || nameSession(req);

          // Generate a new token for the user.
          const token = await generateSessionToken(
            user.id,
            req.body.rememberMe,
          );

          // Create a new session for the user.
          await Session.create({
            id: token.data.payload.iat.toString(),
            user: user.id,
            exp: new Date(token.data.payload.exp * 1000),
            name: sessionName,
          });

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

app.post(
  // POST /api/users/me/sessions
  '/api/users/me/sessions',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  KillSwitch(KillSwitches.ACCOUNT_LOGIN),
  ReverifyIdentity(),
  AutoTrim(),
  SessionPermissionChecker(), // Require a standard browser session
  BodyValidator({
    name: 'string',
    permissionFlags: 'number',
    longLived: new ExtendedValidBodyTypes().boolean().notRequired(),
  }),
  Ratelimit({
    max: 4,
    window: ms('5m'),
    storage: ratelimitStore,
  }),
  async (
    req: Request<
      null,
      null,
      { name: string; permissionFlags: number; longLived?: boolean }
    >,
    res: Response<
      | Cumulonimbus.Structures.ScopedSessionCreate
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Generate a new token for the user.
    const token = await generateSessionToken(
      req.user.id,
      req.body.longLived || false,
    );

    // Create a new session for the user.
    const session = await Session.create({
      id: token.data.payload.iat.toString(),
      user: req.user.id,
      exp: new Date(token.data.payload.exp * 1000),
      name: req.body.name,
      permissionFlags: req.body.permissionFlags,
    });

    logger.debug(
      `User ${req.user.username} (${req.user.id}) created a new session ${req.body.name} (${session.id}).`,
    );

    // Return the new session.
    return res.status(201).json({
      token: token.token,
      id: session.id,
      exp: session.exp.getTime() / 1000,
      name: session.name,
      permissionFlags: session.permissionFlags,
      usedAt: null,
      createdAt: session.createdAt.toISOString(),
      updatedAt: session.updatedAt.toISOString(),
    });
  },
);

app.get(
  // GET /api/users/me/sessions/me
  '/api/users/me/sessions/me',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_READ),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested their current session.`,
    );

    return res.status(200).json({
      id: req.session.id,
      exp: req.session.exp.getTime() / 1000,
      name: req.session.name,
      permissionFlags: req.session.permissionFlags,
      usedAt: req.session.usedAt?.toISOString() || null,
      createdAt: req.session.createdAt.toISOString(),
      updatedAt: req.session.updatedAt.toISOString(),
    });
  },
);

app.get(
  // GET /api/users/me/sessions/:sid
  '/api/users/me/sessions/:sid([0-9]{10})',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_READ),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the session with the given ID.
    const session = await Session.findOne({
      where: {
        user: req.user.id,
        id: req.params.sid,
      },
    });

    // If no session was found, return an InvalidSession error.
    if (!session) return res.status(404).json(new Errors.InvalidSession());

    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested their session ${session.name} (${session.id}).`,
    );

    // Return the session.
    return res.status(200).json({
      id: session.id,
      exp: session.exp.getTime() / 1000,
      name: session.name,
      permissionFlags: session.permissionFlags,
      usedAt: session.usedAt?.toISOString() || null,
      createdAt: session.createdAt.toISOString(),
      updatedAt: session.updatedAt.toISOString(),
    });
  },
);

app.get(
  // GET /api/users/:uid/sessions/:sid
  '/api/users/:uid([0-9]{13})/sessions/:sid([0-9]{10})',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_SESSIONS),
  async (
    req: Request<{ uid: string; sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Find the session with the given ID.
      const session = await Session.findOne({
        where: {
          user: user.id,
          id: req.params.sid,
        },
      });

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested user ${user.username} (${user.id})'s session ${session.name} (${session.id}).`,
      );

      // Return the session.
      return res.status(200).json({
        id: session.id,
        exp: session.exp.getTime() / 1000,
        name: session.name,
        permissionFlags: session.permissionFlags,
        usedAt: session.usedAt?.toISOString() || null,
        createdAt: session.createdAt.toISOString(),
        updatedAt: session.updatedAt.toISOString(),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/me/sessions
  '/api/users/me/sessions',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_READ),
  LimitOffset(0, 50),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      | Cumulonimbus.Structures.List<{ id: string; name: string }>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested their sessions.`,
    );

    const sessions = await Session.findAndCountAll({
      where: {
        user: req.user.id,
      },
      order: [['createdAt', 'DESC']],
      limit: req.limit,
      offset: req.offset,
    });

    // Return the user's sessions.
    return res.status(200).json({
      count: sessions.count,
      items: sessions.rows.map((session) => ({
        id: session.id,
        name: session.name,
      })),
    });
  },
);

app.get(
  // GET /api/users/:uid/sessions
  '/api/users/:uid([0-9]{13})/sessions',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_SESSIONS),
  LimitOffset(0, 50),
  async (
    req: Request<{ uid: string }, null, null>,
    res: Response<
      | Cumulonimbus.Structures.List<{ id: string; name: string }>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      const sessions = await Session.findAndCountAll({
        where: {
          user: user.id,
        },
        order: [['createdAt', 'DESC']],
        limit: req.limit,
        offset: req.offset,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested user ${user.username} (${user.id})'s sessions.`,
      );

      // Return the user's sessions.
      return res.status(200).json({
        count: sessions.count,
        items: sessions.rows.map((session) => ({
          id: session.id,
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
  // DELETE /api/users/me/sessions/me
  '/api/users/me/sessions/me',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_MODIFY),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Delete the current session.
      await req.session.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove their current session.`,
      );

      // Return a success.
      return res.status(200).json(new Success.DeleteSession());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me/sessions/:sid
  '/api/users/me/sessions/:sid([0-9]{10})',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_MODIFY),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the session with the given ID.
    const session = await Session.findOne({
      where: {
        user: req.user.id,
        id: req.params.sid,
      },
    });

    // If no session was found, return an InvalidSession error.
    if (!session) return res.status(404).json(new Errors.InvalidSession());

    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested to remove their session ${session.name} (${session.id}).`,
    );

    try {
      // Delete the session.
      await session.destroy();

      // Return a success.
      return res.status(200).json(new Success.DeleteSession());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/sessions/:sid
  '/api/users/:uid([0-9]{13})/sessions/:sid([0-9]{10})',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_SESSIONS),
  async (
    req: Request<{ uid: string; sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Find the session with the given ID.
      const session = await Session.findOne({
        where: {
          user: user.id,
          id: req.params.sid,
        },
      });

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      await session.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove user ${user.username} (${user.id})'s session ${session.name} (${session.id}).`,
      );

      // Return a success.
      return res.status(200).json(new Success.DeleteSession());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me/sessions
  '/api/users/me/sessions',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_MODIFY),
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Check if they are trying to remove more than 50 sessions.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    // Remove the sessions.
    const { count, rows } = await Session.findAndCountAll({
      where: {
        user: req.user.id,
        id: {
          [Op.in]: req.body.ids,
        },
      },
    });

    await Promise.all(rows.map((session) => session.destroy()));

    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested to remove ${count} of their sessions.`,
    );

    // Return a success.
    return res.status(200).json(new Success.DeleteSessions(count));
  },
);

app.delete(
  // DELETE /api/users/:uid/sessions
  '/api/users/:uid([0-9]{13})/sessions',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_SESSIONS),
  async (
    req: Request<{ uid: string }, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Check if they are trying to remove more than 50 sessions.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Find all of the requested sessions.
      const { rows, count } = await Session.findAndCountAll({
        where: {
          user: user.id,
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // Delete the sessions.
      await Promise.all(rows.map((session) => session.destroy()));

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove ${count} of user ${user.username} (${user.id})'s sessions.`,
      );

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // Delete /api/users/me/sessions/all
  '/api/users/me/sessions/all',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SESSION_MODIFY),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    // Find the sessions that belong to the user.
    const { rows, count } = await Session.findAndCountAll({
      where: {
        user: req.user.id,
        ...{
          id: req.query['include-self']
            ? { [Op.ne]: null }
            : { [Op.ne]: req.session.id },
        },
      },
    });

    // Remove the sessions.
    await Promise.all(rows.map((session) => session.destroy()));

    logger.debug(
      `User ${req.user.username} (${
        req.user.id
      }) requested to remove all of their sessions. (they did${
        req.query['include-self'] ? '' : ' not'
      } include the current session)`,
    );

    // Return a success.
    return res.status(200).json(new Success.DeleteSessions(count));
  },
);

app.delete(
  // DELETE /api/users/:uid/sessions/all
  '/api/users/:uid([0-9]{13})/sessions/all',
  ReverifyIdentity(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_SESSIONS),
  async (
    req: Request<{ uid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the user with the given ID.
      const user = await User.findByPk(req.params.uid);

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Find the user's sessions.
      const { count, rows } = await Session.findAndCountAll({
        where: {
          user: user.id,
        },
      });

      // Remove the sessions.
      await Promise.all(rows.map((session) => session.destroy()));

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested to remove all of user ${user.username} (${user.id})'s sessions.`,
      );

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
