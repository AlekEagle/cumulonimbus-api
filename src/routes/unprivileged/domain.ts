import { logger, app } from "../../index.js";
import { Errors } from "../../utils/TemplateResponses.js";
import Domain from "../../DB/Domain.js";

import { Request, Response } from "express";

logger.debug("Loading unprivileged/domain.ts...");

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
    try {
      if (!req.user) res.status(401).send(new Errors.InvalidSession());
      else {
        try {
          const limit =
              req.query.limit && req.query.limit <= 50 && req.query.limit > 0
                ? req.query.limit
                : 50,
            offset =
              req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
          let domains = await Domain.findAndCountAll({
              limit,
              offset,
              order: [["createdAt", "DESC"]],
            }),
            rows = domains.rows.map((d) => d.toJSON());
          logger.debug(
            `User ${req.user.username} (${req.user.id}) requested ${rows.length} domains.`
          );
          res.status(200).send({ count: domains.count, items: rows });
        } catch (error) {
          throw error;
        }
      }
    } catch (error) {
      throw error;
    }
  }
);

app.get(
  // GET /api/domains/slim
  "/api/domains/slim",
  async (
    req: Request<null, null, null, null>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.DomainSlim>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    try {
      if (!req.user) res.status(401).send(new Errors.InvalidSession());
      else {
        try {
          let domains = await Domain.findAndCountAll({
              order: [["createdAt", "DESC"]],
            }),
            rows = domains.rows.map((d) => {
              let a = d.toJSON();
              return {
                domain: a.domain,
                allowsSubdomains: a.allowsSubdomains,
              };
            });

          logger.debug(
            `User ${req.user.username} (${req.user.id}) requested slim domains.`
          );
          res.status(200).send({ count: domains.count, items: rows });
        } catch (error) {
          throw error;
        }
      }
    } catch (error) {
      throw error;
    }
  }
);

app.get(
  // GET /api/domains/:domain
  "/api/domains/:domain",
  async (
    req: Request<{ domain: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Domain | Cumulonimbus.Structures.Error
    >
  ) => {
    try {
      if (!req.user) res.status(401).send(new Errors.InvalidSession());
      else {
        try {
          let domain = await Domain.findByPk(req.params.domain);

          logger.debug(
            `User ${req.user.username} (${req.user.id}) requested domain ${req.params.domain}.`
          );
          if (domain) res.status(200).send(domain.toJSON());
          else res.status(404).send(new Errors.InvalidDomain());
        } catch (error) {
          throw error;
        }
      }
    } catch (error) {
      throw error;
    }
  }
);
