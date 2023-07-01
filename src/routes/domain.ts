import { logger, app } from "../index.js";
import { Errors, Success } from "../utils/TemplateResponses.js";
import Domain from "../DB/Domain.js";
import User from "../DB/User.js";
import { getInvalidFields, FieldTypeOptions } from "../utils/FieldValidator.js";
import AutoTrim from "../middleware/AutoTrim.js";
import FieldExtractor from "../utils/FieldExtractor.js";

import { Request, Response } from "express";
import { Op } from "sequelize";

logger.debug("Loading: Domain Routes...");

app.get(
  // GET /api/domains
  "/api/domains",
  async (
    req: Request<null, null, null, { limit: number; offset: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Domain>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Normalize the limit and offset.
    const limit =
        req.query.limit && req.query.limit >= -1 && req.query.limit <= 50
          ? req.query.limit
          : 50,
      offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

    try {
      // Get the domains.
      const { count, rows: domains } = await Domain.findAndCountAll({
        limit: limit === -1 ? undefined : limit,
        offset: limit === -1 ? undefined : offset,
        order: [["createdAt", "DESC"]],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched domains.`
      );

      // Return the domains.
      return res.status(200).send({
        count,
        items: domains.map((d) => FieldExtractor(d, ["id", "subdomains"])),
      });
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/domains/:id
  "/api/domains/:id",
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).send(new Errors.InvalidDomain());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched domain ${domain.id}.`
      );

      // Return the domain.
      return res.status(200).send(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.post(
  // POST /api/domains
  "/api/domains",
  AutoTrim(),
  async (
    req: Request<null, null, { id: string; subdomains?: boolean }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // If the user isn't staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the invalid fields.
      const invalidFields = getInvalidFields(req.body, {
        id: "string",
        subdomains: new FieldTypeOptions("boolean", true),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // If the domain already exists, return a DomainExists error.
      if (await Domain.findByPk(req.body.id))
        return res.status(409).send(new Errors.DomainExists());

      // Create the domain.
      const domain = await Domain.create({
        id: req.body.id,
        subdomains: req.body.subdomains ?? false,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) created domain ${domain.id}.`
      );

      // Return the domain.
      return res.status(201).send(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/domains/:id/subdomains
  "/api/domains/:id/subdomains",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { subdomains: boolean }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // If the user isn't staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).send(new Errors.InvalidDomain());

      // Get the invalid fields.
      const invalidFields = getInvalidFields(req.body, {
        subdomains: "boolean",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Update the domain.
      await domain.update({
        allowsSubdomains: req.body.subdomains,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated domain ${domain.id}.`
      );

      // Return the domain.
      return res.status(200).send(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/domains/:id
  "/api/domains/:id",
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // If the user isn't staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).send(new Errors.InvalidDomain());

      // Find all users using the domain.
      const users = await User.findAll({
        where: {
          domain: domain.id,
        },
      });

      // Set all users' domains to the default domain.
      await Promise.all(
        users.map((user) =>
          user.update({
            domain: process.env.DEFAULT_DOMAIN,
            subdomain: null,
          })
        )
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted domain ${domain.id}.`
      );

      // Delete the domain.
      await domain.destroy();

      // Return a success.
      return res.status(200).send(new Success.DeleteDomain());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/domains
  "/api/domains",
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // If the user isn't staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the invalid fields.
      const invalidFields = getInvalidFields(req.body, {
        ids: new FieldTypeOptions("array", false, "string"),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length > 0)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Get the domains.
      const { count, rows: domains } = await Domain.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // If there are no domains, return a InvalidDomain error.
      if (count === 0) return res.status(404).send(new Errors.InvalidDomain());

      // Find all users using the domains.
      const users = await User.findAll({
        where: {
          domain: {
            [Op.in]: domains.map((domain) => domain.id),
          },
        },
      });

      // Set all users' domains to the default domain.
      await Promise.all(
        users.map((user) =>
          user.update({
            domain: process.env.DEFAULT_DOMAIN,
            subdomain: null,
          })
        )
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} domains.`
      );

      // Delete the domains.
      await Promise.all(domains.map((domain) => domain.destroy()));

      // Return a success.
      return res.status(200).send(new Success.DeleteDomains(count));
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
