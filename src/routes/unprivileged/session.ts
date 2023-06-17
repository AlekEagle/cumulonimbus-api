import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import User from "../../DB/User.js";
import { generateToken, nameSession } from "../../utils/Token.js";
import AutoTrim from "../../middleware/AutoTrim.js";
import defaultRateLimitConfig from "../../utils/RateLimitUtils.js";
import {
  getInvalidFields,
  FieldTypeOptions,
} from "../../utils/FieldValidator.js";

import { Request, Response } from "express";
import Bcrypt from "bcrypt";
import { fn, col, where } from "sequelize";
import ExpressRateLimit from "express-rate-limit";

logger.debug("Loading unprivileged/session.ts...");

app.post(
  // POST /api/user/session
  "/api/user/session",
  AutoTrim(["password"]),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: 60 * 1000, // 1 minute
    max: 3,
  }),
  async (
    req: Request<
      null,
      null,
      { username: string; password: string; rememberMe: boolean }
    >,
    res: Response<
      Cumulonimbus.Structures.SuccessfulAuth | Cumulonimbus.Structures.Error
    >
  ) => {
    try {
      let invalidFields = getInvalidFields(req.body, {
        username: "string",
        password: "string",
        rememberMe: new FieldTypeOptions("boolean", true),
      });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Locate user in the database
      let user = await User.findOne({
        where: where(
          fn("lower", col("username")),
          req.body.username.toLowerCase()
        ),
      });

      if (!user) return res.status(404).send(new Errors.InvalidUser());
      if (user.bannedAt) return res.status(403).send(new Errors.Banned());
      let match = await Bcrypt.compare(req.body.password, user.password);
      if (!match) return res.status(401).send(new Errors.InvalidPassword());
      let sessionName =
        (req.headers["x-token-name"] as string) || nameSession(req);
      let token = await generateToken(
        user.id,
        sessionName,
        req.body.rememberMe
      );
      let newSessions = [
        ...user.sessions,
        {
          iat: token.data.payload.iat,
          exp: token.data.payload.exp,
          name: sessionName,
        },
      ];
      await user.update({ sessions: newSessions });
      logger.debug(
        `User ${user.username} (${user.id}) logged in with session ${sessionName}.`
      );
      return res
        .status(201)
        .send({ token: token.token, exp: token.data.payload.exp });
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/user/session
  "/api/user/session",
  async (
    req,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.session) return res.status(401).send(new Errors.InvalidSession());
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested session information.`
    );
    return res.status(200).send({
      iat: req.session.payload.iat,
      exp: req.session.payload.exp,
      name: req.session.payload.name,
      sub: req.session.payload.sub,
    });
  }
);

app.get(
  // GET /api/user/sessions
  "/api/user/sessions",
  async (
    req: Request<null, null, null, { limit: number; offset: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Session>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    const limit =
      req.query.limit && req.query.limit <= 50 && req.query.limit > 0
        ? req.query.limit
        : 50;
    const offset =
      req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
    let user = req.user.toJSON();
    let sessions = user.sessions
      .map((session: Cumulonimbus.Structures.Session) => {
        return { ...session, sub: user.id };
      })
      .reverse()
      .slice(offset, offset + limit);
    logger.debug(`User ${user.username} (${user.id}) requested session list.`);
    return res
      .status(200)
      .send({ items: sessions, count: user.sessions.length });
  }
);

app.get(
  // GET /api/user/session/:iat
  "/api/user/session/:iat([0-9]+)",
  async (
    req: Request<{ iat: string }>,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    let session = req.user.sessions.find(
      (session) => session.iat === Number(req.params.iat)
    );
    if (!session) return res.status(404).send(new Errors.InvalidSession());
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested session ${session.name} (${session.iat}).`
    );
    return res.status(200).send({ ...session, sub: req.user.id });
  }
);

app.delete(
  // DELETE /api/user/session/:iat
  "/api/user/session/:iat([0-9]+)",
  async (
    req: Request<{ iat: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    let session = req.user.sessions.find(
      (session) => session.iat === Number(req.params.iat)
    );
    if (!session) return res.status(404).send(new Errors.InvalidSession());
    let newSessions = req.user.sessions.filter(
      (session) => session.iat !== Number(req.params.iat)
    );
    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted session ${session.name} (${session.iat}).`
    );
    await req.user.update({ sessions: newSessions });
    return res.status(200).send(new Success.DeleteSession());
  }
);

app.delete(
  // DELETE /api/user/sessions
  "/api/user/sessions",
  async (
    req: Request<null, null, { iats: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    const invalidFields = getInvalidFields(req.body, {
      iats: new FieldTypeOptions("array", false, "string"),
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    if (req.body.iats.length < 1 || req.body.iats.length > 50)
      return res.status(400).send(new Errors.MissingFields(["iats"]));

    let newSessions = req.user.sessions.filter(
      (session) => !req.body.iats.includes(session.iat.toString())
    );
    let count = req.user.sessions.length - newSessions.length;
    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted ${count} sessions.`
    );
    await req.user.update({ sessions: newSessions });
    return res.status(200).send(new Success.DeleteSessions(count));
  }
);

app.delete(
  // DELETE /api/user/sessions/all
  "/api/user/sessions/all",
  async (
    req: Request<null, null, null, { "include-self": boolean }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    let newSessions = req.query["include-self"]
      ? []
      : req.user.sessions.filter(
          (session) => session.iat === req.session.payload.iat
        );
    let count = req.user.sessions.length - newSessions.length;
    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted ${count} sessions.`
    );
    await req.user.update({ sessions: newSessions });
    return res.status(200).send(new Success.DeleteSessions(count));
  }
);
