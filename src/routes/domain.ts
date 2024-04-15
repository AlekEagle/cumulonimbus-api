import { logger, app } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import Domain from '../DB/Domain.js';
import User from '../DB/User.js';
import AutoTrim from '../middleware/AutoTrim.js';
import KVExtractor from '../utils/KVExtractor.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import LimitOffset from '../middleware/LimitOffset.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';

import { Request, Response } from 'express';
import { Op } from 'sequelize';

logger.debug('Loading: Domain Routes...');

app.get(
  // GET /api/domains
  '/api/domains',
  LimitOffset(-1, 50),
  SessionChecker(),
  async (
    req: Request<null, null, null, { limit: string; offset: string }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Domain>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the domains.
      const { count, rows: domains } = await Domain.findAndCountAll({
        limit: req.limit === -1 ? undefined : req.limit,
        offset: req.limit === -1 ? undefined : req.offset,
        order: [['createdAt', 'DESC']],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched domains.`,
      );

      // Return the domains.
      return res.status(200).json({
        count,
        items: domains.map((d) =>
          KVExtractor(d.toJSON(), ['id', 'subdomains']),
        ),
      });
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/domains/:id
  '/api/domains/:id',
  SessionChecker(),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).json(new Errors.InvalidDomain());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched domain ${domain.id}.`,
      );

      // Return the domain.
      return res.status(200).json(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.post(
  // POST /api/domains
  '/api/domains',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_DOMAINS),
  AutoTrim(),
  BodyValidator({
    id: 'string',
    subdomains: new ExtendedValidBodyTypes('boolean', true),
  }),
  async (
    req: Request<null, null, { id: string; subdomains?: boolean }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // If the domain already exists, return a DomainExists error.
      if (await Domain.findByPk(req.body.id))
        return res.status(409).json(new Errors.DomainExists());

      // Create the domain.
      const domain = await Domain.create({
        id: req.body.id,
        subdomains: req.body.subdomains ?? false,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) created domain ${domain.id}.`,
      );

      // Return the domain.
      return res.status(201).json(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/domains/:id/subdomains
  '/api/domains/:id/subdomains',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_DOMAINS),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).json(new Errors.InvalidDomain());

      // Update the domain.
      await domain.update({
        subdomains: true,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) allowed subdomains on domain ${domain.id}.`,
      );

      // Return the domain.
      return res.status(200).json(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/domains/:id/subdomains
  '/api/domains/:id/subdomains',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_DOMAINS),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).json(new Errors.InvalidDomain());

      // Update the domain.
      await domain.update({
        subdomains: false,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) disallowed subdomains on domain ${domain.id}.`,
      );

      // Return the domain.
      return res.status(200).json(domain.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/domains/:id
  '/api/domains/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_DOMAINS),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the domain.
      const domain = await Domain.findByPk(req.params.id);

      // If the domain doesn't exist, return a InvalidDomain error.
      if (!domain) return res.status(404).json(new Errors.InvalidDomain());

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
          }),
        ),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted domain ${domain.id}.`,
      );

      // Delete the domain.
      await domain.destroy();

      // Return a success.
      return res.status(200).json(new Success.DeleteDomain());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/domains
  '/api/domains',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_DOMAINS),
  BodyValidator({
    ids: new ExtendedValidBodyTypes('array', false, 'string'),
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Check if they're trying to delete more than 50 domains.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    try {
      // Get the domains.
      const { count, rows: domains } = await Domain.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // If there are no domains, return a InvalidDomain error.
      if (count === 0) return res.status(404).json(new Errors.InvalidDomain());

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
          }),
        ),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} domains.`,
      );

      // Delete the domains.
      await Promise.all(domains.map((domain) => domain.destroy()));

      // Return a success.
      return res.status(200).json(new Success.DeleteDomains(count));
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
