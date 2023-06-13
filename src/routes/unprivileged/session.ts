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
import { Op, fn, col, where } from "sequelize";
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
  // GET /api/session
  "/api/user/session"
);
