import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import { USERNAME_REGEX, EMAIL_REGEX } from "../../utils/Constants.js";
import {
  getInvalidFields,
  FieldTypeOptions,
} from "../../utils/FieldValidator.js";
import SubdomainFormatter from "../../utils/SubdomainFormatter.js";
import AutoTrim from "../../middleware/AutoTrim.js";
import File from "../../DB/File.js";
import Domain from "../../DB/Domain.js";
import User from "../../DB/User.js";

import Bcrypt from "bcrypt";
import { Request, Response } from "express";
import { existsSync } from "node:fs";
import { unlink } from "node:fs/promises";
import { join } from "node:path";
import { Op } from "sequelize";

logger.debug("Loading privileged/account.ts...");

app.get(
  // GET /api/users
  "/api/users",
  async (
    req: Request<null, null, null, { limit: number; offset: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.User>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    const limit =
        req.query.limit && req.query.limit <= 50 && req.query.limit > 0
          ? req.query.limit
          : 50,
      offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      let users = await User.findAndCountAll({
        limit,
        offset,
        order: [["createdAt", "DESC"]],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested ${users.count} users.`
      );

      res.status(200).send({
        count: users.count,
        items: users.rows.map((u) => {
          let a = u.toJSON();
          delete a.password;
          delete a.sessions;
          return a;
        }),
      });
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/user/:id
  "/api/user/:id",
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      let a = user.toJSON();
      delete a.password;
      delete a.sessions;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested user ${user.username} (${user.id}).`
      );

      res.status(200).send(a);
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/user/:id([0-9]+)/username
  "/api/user/:id([0-9]+)/username",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { username: string }, null>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const invalidFields = getInvalidFields(req.body, { username: "string" });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));
      if (!USERNAME_REGEX.test(req.body.username))
        return res.status(400).send(new Errors.InvalidUsername());

      if (await User.findOne({ where: { username: req.body.username } }))
        return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed username of user ${user.username} (${user.id}) to ${req.body.username}.`
      );

      await user.update({ username: req.body.username });
      let a = user.toJSON();
      delete a.password;
      delete a.sessions;
      res.status(200).send(a);
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/user/:id([0-9]+)/email
  "/api/user/:id([0-9]+)/email",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { email: string }, null>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const invalidFields = getInvalidFields(req.body, { email: "string" });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));
      if (!EMAIL_REGEX.test(req.body.email))
        return res.status(400).send(new Errors.InvalidEmail());

      if (await User.findOne({ where: { email: req.body.email } }))
        return res.status(409).send(new Errors.UserExists());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed email of user ${user.username} (${user.id}) to ${req.body.email}.`
      );

      await user.update({ email: req.body.email });
      let a = user.toJSON();
      delete a.password;
      delete a.sessions;
      res.status(200).send(a);
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/user/:id([0-9]+)/password
  "/api/user/:id([0-9]+)/password",
  async (
    req: Request<
      { id: string },
      null,
      { password: string; confirmPassword: string },
      null
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const invalidFields = getInvalidFields(req.body, {
        password: "string",
        confirmPassword: "string",
      });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));
      if (req.body.password !== req.body.confirmPassword)
        return res.status(400).send(new Errors.PasswordsDoNotMatch());

      await user.update({ password: await Bcrypt.hash(req.body.password, 15) });
      let a = user.toJSON();
      delete a.password;
      delete a.sessions;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed password of user ${user.username} (${user.id}).`
      );

      res.status(200).send(a);
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/user/:id([0-9]+)/staff
  "/api/user/:id([0-9]+)/staff",
  async (
    req: Request<{ id: string }, null, { staff: boolean }, null>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const invalidFields = getInvalidFields(req.body, { staff: "boolean" });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      await user.update({ staff: req.body.staff });
      let a = user.toJSON();
      delete a.password;
      delete a.sessions;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed staff status of user ${user.username} (${user.id}) to ${req.body.staff}.`
      );

      res.status(200).send(a);
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/user/:id([0-9]+)/banned
  "/api/user/:id([0-9]+)/banned",
  async (
    req: Request<{ id: string }, null, { banned: boolean }, null>,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const invalidFields = getInvalidFields(req.body, { banned: "boolean" });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      await user.update({ banned: req.body.banned });
      let a = user.toJSON();
      delete a.password;
      delete a.sessions;

      logger.debug(
        `User ${req.user.username} (${req.user.id}) changed banned status of user ${user.username} (${user.id}) to ${req.body.banned}.`
      );

      res.status(200).send(a);
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/user/:id([0-9]+)/domain
  "/api/user/:id([0-9]+)/domain",
  AutoTrim(),
  async (
    req: Request<
      { id: string },
      null,
      { domain: string; subdomain?: string },
      null
    >,
    res: Response<Cumulonimbus.Structures.User | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const invalidFields = getInvalidFields(req.body, {
        domain: "string",
        subdomain: new FieldTypeOptions("string", true),
      });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      const domain = await Domain.findByPk(req.body.domain);
      if (!domain) return res.status(404).send(new Errors.InvalidDomain());

      if (!req.body.subdomain) {
        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed domain of user ${user.username} (${user.id}) to ${domain.domain}.`
        );
        await user.update({ domain: domain.domain, subdomain: null });

        let a = user.toJSON();
        delete a.password;
        delete a.sessions;
        return res.status(200).send(a);
      } else {
        if (!domain.allowsSubdomains)
          return res.status(400).send(new Errors.SubdomainNotSupported());
        const formattedSubdomain = SubdomainFormatter(req.body.subdomain);
        if (formattedSubdomain.length > 63)
          return res
            .status(400)
            .send(new Errors.InvalidSubdomain(formattedSubdomain));

        logger.debug(
          `User ${req.user.username} (${req.user.id}) changed domain of user ${user.username} (${user.id}) to ${formattedSubdomain}.${domain.domain}.`
        );

        await user.update({
          domain: domain.domain,
          subdomain: formattedSubdomain,
        });

        let a = user.toJSON();
        delete a.password;
        delete a.sessions;
        return res.status(200).send(a);
      }
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/user/:id([0-9]+)
  "/api/user/:id([0-9]+)",
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      const files = await File.findAll({ where: { userID: user.id } });

      for (const file of files) {
        await unlink(join(process.env.BASE_UPLOAD_PATH, file.filename));

        if (
          existsSync(
            join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
          )
        )
          await unlink(
            join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
          );

        await file.destroy();
      }

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted user ${user.username} (${user.id}).`
      );

      await user.destroy();

      return res.status(200).send(new Success.DeleteUser());
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users
  "/api/users",
  async (
    req: Request<null, null, { ids: string[] }, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      const invalidFields = getInvalidFields(req.body, {
        ids: new FieldTypeOptions("array", false, "string"),
      });

      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      if (req.body.ids.length < 1 || req.body.ids.length > 50)
        return res.status(400).send(new Errors.MissingFields(["ids"]));

      const users = await User.findAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      for (const user of users) {
        const files = await File.findAll({ where: { userID: user.id } });

        for (const file of files) {
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.filename));

          if (
            existsSync(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
            )
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
            );

          await file.destroy();
        }

        logger.debug(
          `User ${req.user.username} (${req.user.id}) deleted user ${user.username} (${user.id}).`
        );

        await user.destroy();
      }

      return res.status(200).send(new Success.DeleteUsers(users.length));
    } catch (error) {
      logger.error(error);
      res.status(500).send(new Errors.Internal());
    }
  }
);
