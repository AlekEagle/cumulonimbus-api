import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import User from "../../DB/User.js";

import { Request, Response } from "express";

logger.debug("Loading privileged/session.ts...");

app.get(
  // GET /api/user/:id/sessions
  "/api/user/:id([0-9]+)/sessions",
  async (
    req: Request<{ id: string }, null, null, { limit: number; offset: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Session>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());
    const limit =
      req.query.limit && req.query.limit <= 50 && req.query.limit > 0
        ? req.query.limit
        : 50;
    const offset =
      req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
    let user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).send(new Errors.InvalidUser());
    let sessions = user.sessions
      .map((session: Cumulonimbus.Structures.Session) => {
        return { ...session, sub: user.id };
      })
      .reverse()
      .slice(offset, offset + limit);
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested session list for user ${user.username} (${user.id}).`
    );
    return res
      .status(200)
      .send({ items: sessions, count: user.sessions.length });
  }
);

app.get(
  // GET /api/user/:id/session/:iat
  "/api/user/:id([0-9]+)/session/:iat([0-9]+)",
  async (
    req: Request<{ id: string; iat: string }>,
    res: Response<
      Cumulonimbus.Structures.Session | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());
    let user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).send(new Errors.InvalidUser());
    let session = user.sessions.find(
      (session) => session.iat === Number(req.params.iat)
    );
    if (!session) return res.status(404).send(new Errors.InvalidSession());
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested session ${session.name} (${session.iat}) for user ${user.username} (${user.id}).`
    );
    return res.status(200).send({ ...session, sub: user.id });
  }
);

app.delete(
  // DELETE /api/user/:id/session/:iat
  "/api/user/:id([0-9]+)/session/:iat([0-9]+)",
  async (
    req: Request<{ id: string; iat: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());
    let user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).send(new Errors.InvalidUser());

    if (
      !user.sessions.some((session) => session.iat === Number(req.params.iat))
    )
      return res.status(404).send(new Errors.InvalidSession());

    let newSessions = user.sessions.filter(
      (session) => session.iat !== Number(req.params.iat)
    );
    await user.update({ sessions: newSessions });
    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted session ${req.params.iat} for user ${user.username} (${user.id}).`
    );
    return res.status(200).send(new Success.DeleteSession());
  }
);

app.delete(
  // DELETE /api/user/:id/sessions
  "/api/user/:id([0-9]+)/sessions",
  async (
    req: Request<{ id: string }, null, { iats: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());
    let user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).send(new Errors.InvalidUser());
    let newSessions = user.sessions.filter(
      (session) => !req.body.iats.includes(session.iat.toString())
    );
    let count = user.sessions.length - newSessions.length;
    await user.update({ sessions: newSessions });
    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted ${count} sessions for user ${user.username} (${user.id}).`
    );
    return res.status(200).send(new Success.DeleteSession());
  }
);

app.delete(
  // DELETE /api/user/:id/sessions/all
  "/api/user/:id([0-9]+)/sessions/all",
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());
    let user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).send(new Errors.InvalidUser());
    await user.update({ sessions: [] });
    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted all sessions for user ${user.username} (${user.id}).`
    );
    return res.status(200).send(new Success.DeleteSession());
  }
);
