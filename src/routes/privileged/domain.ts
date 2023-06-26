import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import {
  getInvalidFields,
  FieldTypeOptions,
} from "../../utils/FieldValidator.js";
import AutoTrim from "../../middleware/AutoTrim.js";
import Domain from "../../DB/Domain.js";

import { Request, Response } from "express";
import { Op } from "sequelize";
import User from "../../DB/User.js";

logger.debug("Loading privileged/domain.ts...");

app.post(
  // POST /api/domain
  "/api/domains",
  AutoTrim(),
  async (
    req: Request<null, null, { domain: string; allowSubdomains?: boolean }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    let invalidFields = getInvalidFields(req.body, {
      domain: "string",
      allowSubdomains: new FieldTypeOptions("boolean", true),
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    if (await Domain.findByPk(req.body.domain))
      return res.status(409).send(new Errors.DomainExists());

    logger.debug(
      `User ${req.user.username} (${req.user.id}) is creating domain ${req.body.domain}...`
    );

    let domain = await Domain.create({
      domain: req.body.domain,
      allowsSubdomains: req.body.allowSubdomains ?? false,
    });

    return res.status(201).send(domain.toJSON());
  }
);

app.patch(
  // PATCH /api/domain/:domain
  "/api/domains/:domain",
  AutoTrim(),
  async (
    req: Request<{ domain: string }, null, { allowSubdomains: boolean }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    let invalidFields = getInvalidFields(req.body, {
      allowSubdomains: "boolean",
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    let domain = await Domain.findByPk(req.params.domain);

    if (!domain) return res.status(404).send(new Errors.InvalidDomain());

    await domain.update({
      allowsSubdomains: req.body.allowSubdomains ?? domain.allowsSubdomains,
    });

    logger.debug(
      `User ${req.user.username} (${req.user.id}) is updating domain ${req.params.domain}...`
    );

    return res.status(200).send(domain.toJSON());
  }
);

app.delete(
  // DELETE /api/domain/:domain
  "/api/domains/:domain",
  async (
    req: Request<{ domain: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    let domain = await Domain.findByPk(req.params.domain);

    if (!domain) return res.status(404).send(new Errors.InvalidDomain());

    let usersUsingDomain = await User.findAll({
      where: {
        domains: req.params.domain,
      },
    });

    // Reset domains for users using the domain
    for (let user of usersUsingDomain)
      await user.update({ domain: process.env.DEFAULT_DOMAIN });

    logger.debug(
      `User ${req.user.username} (${req.user.id}) is deleting domain ${req.params.domain}...`
    );

    await domain.destroy();

    return res.status(200).send(new Success.DeleteDomain());
  }
);

app.delete(
  // DELETE /api/domains
  "/api/domains",
  async (
    req: Request<null, null, { domains: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    let invalidFields = getInvalidFields(req.body, {
      domains: new FieldTypeOptions("array", false, "string"),
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    let domains = await Domain.findAll({
      where: {
        domain: {
          [Op.in]: req.body.domains,
        },
      },
    });

    if (domains.length === 0)
      return res.status(404).send(new Errors.InvalidDomain());

    let usersUsingDomains = await User.findAll({
      where: {
        domains: req.body.domains,
      },
    });

    // Reset domains for users using the domains
    for (let user of usersUsingDomains)
      await user.update({ domain: process.env.DEFAULT_DOMAIN });

    logger.debug(
      `User ${req.user.username} (${req.user.id}) is deleting ${domains.length} domains...`
    );

    for (let domain of domains) await domain.destroy();

    return res.status(200).send(new Success.DeleteDomains(domains.length));
  }
);
