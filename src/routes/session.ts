import { logger, app } from "../index.js";
import { Errors, Success } from "../utils/TemplateResponses.js";
import User from "../DB/User.js";
import { getInvalidFields, FieldTypeOptions } from "../utils/FieldValidator.js";
import AutoTrim from "../middleware/AutoTrim.js";
import defaultRateLimitConfig from "../utils/RateLimitUtils.js";
import { generateToken, nameSession } from "../utils/Token.js";

import { Request, Response } from "express";
import Bcrypt from "bcrypt";
import { fn, col, where } from "sequelize";
import ExpressRateLimit from "express-rate-limit";

logger.debug("Loading: Session Routes...");

app.post(
  // POST /api/login
  "/api/login",
  AutoTrim(),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: 60 * 1000, // 1 minute
    max: 3,
  }),
  async (
    req: Request<
      null,
      null,
      {
        username: string;
        password: string;
        rememberMe?: boolean;
      }
    >,
    res: Response<
      Cumulonimbus.Structures.SuccessfulAuth | Cumulonimbus.Structures.Error
    >
  ) => {
    // If the user is already logged in, return an InvalidSession error.
    if (req.user) return res.status(401).json(new Errors.InvalidSession());

    try {
      // Check for missing fields
      const missingFields = getInvalidFields(req.body, {
        username: "string",
        password: "string",
        rememberMe: new FieldTypeOptions("boolean", true),
      });

      // If there are missing fields, return a MissingFields error.
      if (missingFields.length)
        return res.status(400).json(new Errors.MissingFields(missingFields));

      // Find a user with the given username.
      let user = await User.findOne({
        where: where(
          fn("lower", col("username")),
          req.body.username.toLowerCase()
        ),
      });

      // If no user was found, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // If the user is banned, return a Banned error.
      if (user.bannedAt) return res.status(403).json(new Errors.Banned());

      // Compare the given password with the user's password.
      if (!(await Bcrypt.compare(req.body.password, user.password)))
        return res.status(401).json(new Errors.InvalidPassword());

      // Generate a session name for the new session.
      let sessionName =
        (req.headers["x-token-name"] as string) || nameSession(req);

      // Generate a new token for the user.
      let token = await generateToken(user.id, req.body.rememberMe);

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
  }
);

app.get(
  // GET /api/users/:uid/sessions/:sid
  "/api/users/:uid([0-9]{13}|me)/sessions/:sid([0-9]{10}|me)",
  async (
    req: Request<{ uid: string; sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >
  ) => {
    // If the user is not logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    // Check if the user is requesting a session that belongs to them.
    if (req.params.uid === "me" || req.params.uid === req.user.id) {
      // Check if the user is requesting the current session.
      if (req.params.sid === "me") {
        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested their current session.`
        );

        // Get the current session.
        let session = req.user.sessions.find(
          (session) => session.iat === req.session.payload.iat
        );

        return res.status(200).send({
          id: session.iat,
          exp: session.exp,
          name: session.name,
        });
      }

      // Find the session with the given ID.
      let session = req.user.sessions.find(
        (session) => session.iat === parseInt(req.params.sid)
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested their session ${session.name} (${session.iat}).`
      );

      // Return the session.
      return res.status(200).send({
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
        (session) => session.iat === parseInt(req.params.sid)
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested user ${user.username} (${user.id})'s session ${session.name} (${session.iat}).`
      );

      // Return the session.
      return res.status(200).send({
        id: session.iat,
        exp: session.exp,
        name: session.name,
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/users/:uid/sessions
  "/api/users/:uid([0-9]{13}|me)/sessions",
  async (
    req: Request<
      { uid: string },
      null,
      null,
      { limit: number; offset: number }
    >,
    res: Response<
      | Cumulonimbus.Structures.List<{ id: number; name: string }>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    // If the user is not logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    // Normalize the limit and offset.
    const limit =
        req.query.limit && req.query.limit >= 0 && req.query.limit <= 50
          ? req.query.limit
          : 50,
      offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

    // Check if the user is requesting sessions that belong to them.
    if (req.params.uid === "me" || req.params.uid === req.user.id) {
      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested their sessions.`
      );

      // Return the user's sessions.
      return res.status(200).send({
        count: req.user.sessions.length,
        items: req.user.sessions
          .slice(offset, offset + limit)
          .map((session) => ({
            id: session.iat,
            name: session.name,
          })),
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

      // Return the user's sessions.
      return res.status(200).send({
        count: user.sessions.length,
        items: user.sessions.slice(offset, offset + limit).map((session) => ({
          id: session.iat,
          name: session.name,
        })),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/:uid/sessions/:sid
  "/api/users/:uid([0-9]{13}|me)/sessions/:sid([0-9]{10}|me)",
  async (
    req: Request<{ uid: string; sid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If the user is not logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    // Check if the user is requesting a session that belongs to them.
    if (req.params.uid === "me" || req.params.uid === req.user.id) {
      // Check if the user is requesting the current session.
      if (req.params.sid === "me") {
        // Remove the current session.
        let sessions = req.user.sessions.filter(
          (session) => session.iat !== req.session.payload.iat
        );

        // Update the user's sessions.
        await req.user.update({ sessions });

        // Return a success.
        return res.status(200).json(new Success.DeleteSession());
      }

      // Find the session with the given ID.
      let session = req.user.sessions.find(
        (session) => session.iat === parseInt(req.params.sid)
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      // Remove the session.
      let sessions = req.user.sessions.filter(
        (session) => session.iat !== parseInt(req.params.sid)
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
        (session) => session.iat === parseInt(req.params.sid)
      );

      // If no session was found, return an InvalidSession error.
      if (!session) return res.status(404).json(new Errors.InvalidSession());

      // Remove the session.
      let sessions = user.sessions.filter(
        (session) => session.iat !== parseInt(req.params.sid)
      );

      // Update the user's sessions.
      await user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSession());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/:uid/sessions
  "/api/users/:uid([0-9]{13}|me)/sessions",
  async (
    req: Request<{ uid: string }, null, { sids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If the user is not logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    // Check if the user is requesting sessions that belong to them.
    if (req.params.uid === "me" || req.params.uid === req.user.id) {
      // Check if the user is requesting the current session.
      if (req.body.sids.includes("me"))
        // Replace `me` with the current session ID.
        req.body.sids[req.body.sids.indexOf("me")] =
          req.session.payload.iat.toString();

      // Remove the sessions.
      let sessions = req.user.sessions.filter(
        (session) => !req.body.sids.includes(session.iat.toString())
      );

      // Count the number of sessions removed.
      let count = req.user.sessions.length - sessions.length;

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
        (session) => !req.body.sids.includes(session.iat.toString())
      );

      // Count the number of sessions removed.
      let count = user.sessions.length - sessions.length;

      // Update the user's sessions.
      await user.update({ sessions });

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/:uid/sessions/all
  "/api/users/:uid([0-9]{13}|me)/sessions/all",
  async (
    req: Request<{ uid: string }, null, null, { "include-self"?: boolean }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If the user is not logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    // Check if the user is requesting sessions that belong to them.
    if (req.params.uid === "me" || req.params.uid === req.user.id) {
      // Remove the sessions.
      let sessions = req.user.sessions.filter(
        (session) =>
          req.query["include-self"] || session.iat !== req.session.payload.iat
      );

      // Count the number of sessions removed.
      let count = req.user.sessions.length - sessions.length;

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

      // Update the user's sessions.
      await user.update({ sessions: [] });

      // Return a success.
      return res.status(200).json(new Success.DeleteSessions(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  }
);
