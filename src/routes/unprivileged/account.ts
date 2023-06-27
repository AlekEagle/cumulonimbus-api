import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import { USERNAME_REGEX, EMAIL_REGEX } from "../../utils/Constants.js";
import {
  getInvalidFields,
  FieldTypeOptions,
} from "../../utils/FieldValidator.js";
import SubdomainFormatter from "../../utils/SubdomainFormatter.js";
import AutoTrim from "../../middleware/AutoTrim.js";
import Domain from "../../DB/Domain.js";
import User from "../../DB/User.js";
import { generateToken, nameSession } from "../../utils/Token.js";
import defaultRateLimitConfig from "../../utils/RateLimitUtils.js";
import FieldExtractor from "../../utils/FieldExtractor.js";

import { Request, Response } from "express";
import Bcrypt from "bcrypt";
import { Op } from "sequelize";
import ExpressRateLimit from "express-rate-limit";

logger.debug("Loading unprivileged/account.ts...");

app.get(
  // GET /api/users/me
  "/api/users/me",
  async (
    req: Request,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    logger.debug(
      `User ${req.user.username} (${req.user.id}) requested their user data.`
    );
    // Convert the user object to JSON, remove the password and sessions fields, and send it.

    return res
      .status(200)
      .send(FieldExtractor(req.user.toJSON(), ["password", "sessions"], true));
  }
);

app.put(
  // PUT /api/users/me/username
  "/api/users/me/username",
  AutoTrim(["password"]),
  async (
    req: Request<null, null, { username: string; password: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the request body is missing the username or password fields, return a MissingFields error.
    const invalidFields = getInvalidFields(req.body, {
      username: "string",
      password: "string",
    });
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    // If the username is not valid, return a MissingFields error.
    if (!req.body.username.match(USERNAME_REGEX))
      return res.status(400).send(new Errors.InvalidUsername());

    try {
      // Compare the password in the request body to the password in the database.
      const match = await Bcrypt.compare(req.body.password, req.user.password);
      // If the passwords do not match, return an InvalidPassword error.
      if (!match) return res.status(401).send(new Errors.InvalidPassword());

      // Check if the username is already taken.
      const existingUser = await User.findOne({
        where: { username: req.body.username },
      });
      // If the username is already taken, return a UserExists error.
      if (existingUser) return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their username to ${req.body.username}`
      );

      // Update the user's username and send the updated user object.
      await req.user.update({ username: req.body.username });
      return res
        .status(200)
        .send(
          FieldExtractor(req.user.toJSON(), ["password", "sessions"], true)
        );
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/me/email
  "/api/users/me/email",
  AutoTrim(["password"]),
  async (
    req: Request<null, null, { email: string; password: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the request body is missing the email or password fields, return a MissingFields error.
    const invalidFields = getInvalidFields(req.body, {
      email: "string",
      password: "string",
    });
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    // If the email is not valid, return a MissingFields error.
    if (!req.body.email.match(EMAIL_REGEX))
      return res.status(400).send(new Errors.InvalidEmail());

    try {
      // Compare the password in the request body to the password in the database.
      const match = await Bcrypt.compare(req.body.password, req.user.password);
      // If the passwords do not match, return an InvalidPassword error.
      if (!match) return res.status(401).send(new Errors.InvalidPassword());

      // Check if the email is already taken.
      const existingUser = await User.findOne({
        where: { email: req.body.email },
      });
      // If the email is already taken, return a UserExists error.
      if (existingUser) return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their email to ${req.body.email}`
      );

      // Update the user's email and send the updated user object.
      await req.user.update({ email: req.body.email });
      return res
        .status(200)
        .send(
          FieldExtractor(req.user.toJSON(), ["password", "sessions"], true)
        );
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/me/password
  "/api/users/me/password",
  async (
    req: Request<
      null,
      null,
      { password: string; newPassword: string; confirmNewPassword: string }
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the request body is missing the password, newPassword, or confirmNewPassword fields, return a MissingFields error.
    const invalidFields = getInvalidFields(req.body, {
      password: "string",
      newPassword: "string",
      confirmNewPassword: "string",
    });
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      // Compare the password in the request body to the password in the database.
      const match = await Bcrypt.compare(req.body.password, req.user.password);
      // If the passwords do not match, return an InvalidPassword error.
      if (!match) return res.status(401).send(new Errors.InvalidPassword());

      // If the new password and the confirmation password do not match, return a PasswordsDoNotMatch error.
      if (req.body.newPassword !== req.body.confirmNewPassword)
        return res.status(400).send(new Errors.PasswordsDoNotMatch());

      const hashedPassword = await Bcrypt.hash(req.body.newPassword, 15);

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed their password.`
      );

      // Update the user's password and send the updated user object.
      await req.user.update({ password: hashedPassword });
      return res
        .status(200)
        .send(
          FieldExtractor(req.user.toJSON(), ["password", "sessions"], true)
        );
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/users/me/domain
  "/api/users/me/domain",
  AutoTrim(),
  async (
    req: Request<null, null, { domain: string; subdomain: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the request body is missing the domain or subdomain fields, return a MissingFields error.
    const invalidFields = getInvalidFields(req.body, {
      domain: "string",
      subdomain: new FieldTypeOptions("string", true),
    });
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      // Check if the domain exists.
      const domain = await Domain.findByPk(req.body.domain);
      // If the domain does not exist, return an InvalidDomain error.
      if (!domain) return res.status(404).send(new Errors.InvalidDomain());

      // If there is no subdomain, set the user's domain and set the subdomain to null.
      if (!req.body.subdomain) {
        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their domain to ${req.body.domain}`
        );
        await req.user.update({ domain: req.body.domain, subdomain: null });
        return res
          .status(200)
          .send(
            FieldExtractor(req.user.toJSON(), ["password", "sessions"], true)
          );
      } else {
        // If the domain does not allow subdomains, return a SubdomainNotSupported error.
        if (!domain.allowsSubdomains)
          return res.status(400).send(new Errors.SubdomainNotAllowed());
        // Format the subdomain.
        const formattedSubdomain = SubdomainFormatter(req.body.subdomain);
        // Check if the subdomain exceeds the maximum length.
        if (formattedSubdomain.length > 63)
          return res.status(400).send(new Errors.SubdomainTooLong());

        // Update the user's domain and subdomain and send the updated user object.
        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their domain to ${formattedSubdomain}.${req.body.domain}`
        );

        await req.user.update({
          domain: req.body.domain,
          subdomain: formattedSubdomain,
        });
        return res
          .status(200)
          .send(
            FieldExtractor(req.user.toJSON(), ["password", "sessions"], true)
          );
      }
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/me
  "/api/users/me",
  AutoTrim(["password"]),
  async (
    req: Request<null, null, { username: string; password: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the request body is missing the username or password fields, return a MissingFields error.
    const invalidFields = getInvalidFields(req.body, {
      username: "string",
      password: "string",
    });
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    // If the username does not match the username of the user in the session, return an InvalidUsername error.
    if (req.body.username !== req.user.username)
      return res.status(401).send(new Errors.InvalidUsername());

    try {
      // Compare the password in the request body to the password in the database.
      const match = await Bcrypt.compare(req.body.password, req.user.password);
      // If the passwords do not match, return an InvalidPassword error.
      if (!match) return res.status(401).send(new Errors.InvalidPassword());
      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted their account.`
      );
      // Delete the user and send the deleted user object.
      await req.user.destroy();
      return res.status(200).send(new Success.DeleteUser());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.post(
  // POST /api/register
  "/api/register",
  AutoTrim(["password", "confirmPassword"]),
  ExpressRateLimit({
    ...defaultRateLimitConfig,
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1,
  }),
  async (
    req: Request<
      null,
      null,
      {
        username: string;
        password: string;
        confirmPassword: string;
        email: string;
        rememberMe?: boolean;
      }
    >,
    res: Response<
      Cumulonimbus.Structures.SuccessfulAuth | Cumulonimbus.Structures.Error
    >
  ) => {
    // If someone attempts to register while logged in, return an InvalidSession error.
    if (req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the request body is missing the username, password, confirmPassword, or email fields, return a MissingFields error.
    const invalidFields = getInvalidFields(req.body, {
      username: "string",
      password: "string",
      confirmPassword: "string",
      email: "string",
      rememberMe: new FieldTypeOptions("boolean", true),
    });
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    // If the password and confirmPassword fields do not match, return a PasswordsDoNotMatch error.
    if (req.body.password !== req.body.confirmPassword)
      return res.status(400).send(new Errors.PasswordsDoNotMatch());

    // If the username or email do not match their respective RegExp, return an InvalidUsername or InvalidEmail error.
    if (!req.body.username.match(USERNAME_REGEX))
      return res.status(400).send(new Errors.InvalidUsername());

    if (!req.body.email.match(EMAIL_REGEX))
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

      // Generate a session token.
      const token = await generateToken(
        now,
        nameSession(req),
        req.body.rememberMe
      );

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
            name: token.data.payload.name,
          },
        ],
      });
      logger.debug(`User ${user.username} (${user.id}) created an account.`);
      return res
        .status(201)
        .send({ token: token.token, exp: token.data.payload.exp });
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
