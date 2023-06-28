import { logger, app } from "../index.js";
import { Errors, Success } from "../utils/TemplateResponses.js";
import {
  USERNAME_REGEX,
  EMAIL_REGEX,
  PASSWORD_HASH_ROUNDS,
} from "../utils/Constants.js";
import { getInvalidFields, FieldTypeOptions } from "../utils/FieldValidator.js";
import SubdomainFormatter from "../utils/SubdomainFormatter.js";
import AutoTrim from "../middleware/AutoTrim.js";
import Domain from "../DB/Domain.js";
import User from "../DB/User.js";
import File from "../DB/File.js";
import { generateToken, nameSession } from "../utils/Token.js";
import defaultRateLimitConfig from "../utils/RateLimitUtils.js";
import FieldExtractor from "../utils/FieldExtractor.js";

import { Request, Response } from "express";
import Bcrypt from "bcrypt";
import { Op } from "sequelize";
import ExpressRateLimit from "express-rate-limit";
import { join } from "node:path";
import { unlink } from "node:fs/promises";
import { existsSync } from "node:fs";

logger.debug("Loading: User Routes...");

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
      logger.debug(`User ${user.username} (${user.id}) account created.`);
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
  // GET /api/users
  "/api/users",
  async (
    req: Request<
      null,
      null,
      null,
      {
        limit?: number;
        offset?: number;
      }
    >,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.User>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());
    // Normalize the limit and offset.
    const limit =
        req.query.limit && req.query.limit >= 0 && req.query.limit <= 50
          ? req.query.limit
          : 50,
      offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

    try {
      // Get the users.
      const { count, rows: users } = await User.findAndCountAll({
        limit,
        offset,
        order: [["createdAt", "DESC"]],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched users. (offset: ${offset}, limit: ${limit})`
      );

      // Send the users.
      return res.status(200).send({
        count,
        items: users.map((user) => FieldExtractor(user, ["id", "username"])),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/users/:id
  "/api/users/:id([0-9]{13}|me)",
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the user is requesting their own user object.
    if (req.params.id === "me" || req.params.id === req.user.id) {
      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched their own user object.`
      );
      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(req.user, ["password", "sessions"], true));
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
        `User ${req.user.username} (${req.user.id}) fetched user ${user.username} (${user.id}).`
      );

      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/:id/username
  "/api/users/:id([0-9]{13}|me)/username",
  async (
    req: Request<{ id: string }, null, { username: string; password?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the user wants to modify their own username.
    if (req.params.id === "me" || req.params.id === req.user.id) {
      try {
        // Check for required fields.
        const invalidFields = getInvalidFields(req.body, {
          username: "string",
          password: "string",
        });

        // Check if the username is valid.
        if (
          !invalidFields.includes("username") &&
          USERNAME_REGEX.test(req.body.username)
        )
          invalidFields.push("username");

        // If there are invalid fields, return a MissingFields error.
        if (invalidFields.length)
          return res.status(400).send(new Errors.MissingFields(invalidFields));

        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Check if the username is already taken.
        if (await User.findOne({ where: { username: req.body.username } }))
          return res.status(409).send(new Errors.UserExists());

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their username to ${req.body.username}.`
        );

        // Update the username.
        await req.user.update({ username: req.body.username });

        // Send the user object.
        return res
          .status(200)
          .send(FieldExtractor(req.user, ["password", "sessions"], true));
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

      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        username: "string",
      });

      // Check if the username is valid.
      if (
        !invalidFields.includes("username") &&
        USERNAME_REGEX.test(req.body.username)
      )
        invalidFields.push("username");

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Check if the username is already taken.
      if (await User.findOne({ where: { username: req.body.username } }))
        return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s username to ${req.body.username}.`
      );

      // Update the username.
      await user.update({ username: req.body.username });

      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/:id/email
  "/api/users/:id([0-9]{13}|me)/email",
  async (
    req: Request<{ id: string }, null, { email: string; password?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the user wants to modify their own email.
    if (req.params.id === "me" || req.params.id === req.user.id) {
      try {
        // Check for required fields.
        const invalidFields = getInvalidFields(req.body, {
          email: "string",
          password: "string",
        });

        // Check if the email is valid.
        if (
          !invalidFields.includes("email") &&
          EMAIL_REGEX.test(req.body.email)
        )
          invalidFields.push("email");

        // If there are invalid fields, return a MissingFields error.
        if (invalidFields.length)
          return res.status(400).send(new Errors.MissingFields(invalidFields));

        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Check if the email is already taken.
        if (await User.findOne({ where: { email: req.body.email } }))
          return res.status(409).send(new Errors.UserExists());

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their email to ${req.body.email}.`
        );

        // Update the email.
        await req.user.update({ email: req.body.email });

        // Send the user object.
        return res
          .status(200)
          .send(FieldExtractor(req.user, ["password", "sessions"], true));
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

      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        email: "string",
      });

      // Check if the email is valid.
      if (!invalidFields.includes("email") && EMAIL_REGEX.test(req.body.email))
        invalidFields.push("email");

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Check if the email is already taken.
      if (await User.findOne({ where: { email: req.body.email } }))
        return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s email to ${req.body.email}.`
      );

      // Update the email.
      await user.update({ email: req.body.email });

      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/:id/password
  "/api/users/:id([0-9]{13}|me)/password",
  async (
    req: Request<
      { id: string },
      null,
      { password?: string; newPassword: string; confirmNewPassword: string }
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the user wants to modify their own password.
    if (req.params.id === "me" || req.params.id === req.user.id) {
      try {
        // Check for required fields.
        const invalidFields = getInvalidFields(req.body, {
          password: "string",
          newPassword: "string",
          confirmNewPassword: "string",
        });

        // If there are invalid fields, return a MissingFields error.
        if (invalidFields.length)
          return res.status(400).send(new Errors.MissingFields(invalidFields));

        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Check if the new password matches the confirmation.
        if (req.body.newPassword !== req.body.confirmNewPassword)
          return res.status(400).send(new Errors.PasswordsDoNotMatch());

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed their password.`
        );

        // Update the password.
        await req.user.update({
          password: await Bcrypt.hash(
            req.body.newPassword,
            PASSWORD_HASH_ROUNDS
          ),
        });

        // Send the user object.
        return res
          .status(200)
          .send(FieldExtractor(req.user, ["password", "sessions"], true));
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

      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        newPassword: "string",
        confirmNewPassword: "string",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Check if the new password matches the confirmation.
      if (req.body.newPassword !== req.body.confirmNewPassword)
        return res.status(400).send(new Errors.PasswordsDoNotMatch());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s password.`
      );

      // Update the password.
      await user.update({
        password: await Bcrypt.hash(req.body.newPassword, PASSWORD_HASH_ROUNDS),
      });

      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/:id/staff
  "/api/users/:id([0-9]{13})/staff",
  async (
    req: Request<{ id: string }, null, { staff: boolean }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        staff: "boolean",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s staff status to ${req.body.staff}.`
      );

      // Update the staff status.
      await user.update({ staff: req.body.staff });

      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/:id/ban
  "/api/users/:id([0-9]{13})/ban",
  async (
    req: Request<{ id: string }, null, { banned: boolean }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the user.
      const user = await User.findByPk(req.params.id);

      // If the user does not exist, return a InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        banned: "boolean",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed user ${user.username} (${user.id})'s banned status to ${req.body.banned}.`
      );

      // Update the banned status.
      await user.update({ banned: req.body.banned ? new Date() : null });

      // Send the user object.
      return res
        .status(200)
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/users/:id/domain
  "/api/users/:id([0-9]{13}|me)/domain",
  async (
    req: Request<{ id: string }, null, { domain: string; subdomain?: string }>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the user is trying to change their own domain.
    if (req.params.id === "me" || req.params.id === req.user.id) {
      try {
        // Check for required fields.
        const invalidFields = getInvalidFields(req.body, {
          domain: "string",
          subdomain: new FieldTypeOptions("string", true),
        });

        // If there are invalid fields, return a MissingFields error.
        if (invalidFields.length)
          return res.status(400).send(new Errors.MissingFields(invalidFields));

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
          .send(FieldExtractor(req.user, ["password", "sessions"], true));
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

      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        domain: "string",
        subdomain: new FieldTypeOptions("string", true),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

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
        .send(FieldExtractor(user, ["password", "sessions"], true));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/:id
  "/api/users/:id([0-9]{13}|me)",
  async (
    req: Request<
      { id: string },
      null,
      { username?: string; password?: string }
    >,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the user is trying to delete their own account.
    if (req.params.id === "me" || req.params.id === req.user.id) {
      try {
        // Check for required fields.
        const invalidFields = getInvalidFields(req.body, {
          username: "string",
          password: "string",
        });

        // If there are invalid fields, return a MissingFields error.
        if (invalidFields.length)
          return res.status(400).send(new Errors.MissingFields(invalidFields));

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
                join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
              )
            )
              await unlink(
                join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
              );

            // Delete the file from the disk.
            await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

            // Delete the file from the database.
            await file.destroy();
          })
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
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        })
      );

      // Delete the user.
      await user.destroy();

      return res.status(200).send(new Success.DeleteUser());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users
  "/api/users",
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return a InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Check for required fields.
      const invalidFields = getInvalidFields(req.body, {
        ids: new FieldTypeOptions("array", false, "string"),
      });

      // Check if the ids field exceeds the maximum length.
      if (req.body.ids.length > 50 && !invalidFields.includes("ids"))
        invalidFields.push("ids");

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

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
                  join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
                )
              )
                await unlink(
                  join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
                );

              // Delete the file from the disk.
              await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

              // Delete the file from the database.
              await file.destroy();
            })
          );

          // Delete the user.
          await user.destroy();
        })
      );

      return res.status(200).send(new Success.DeleteUsers(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
