import { Cumulonimbus } from "../..";
import { Op } from "sequelize";
import Multer from "multer";
import User from "../../utils/DB/User";
import {
  getInvalidFields,
  ResponseConstructors,
} from "../../utils/RequestUtils";
import Domain from "../../utils/DB/Domain";
import AutoTrim from "../../utils/AutoTrim";

const AdminDomainEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: "post",
    path: "/domain",
    preHandlers: [Multer().none(), AutoTrim()],
    async handler(
      req: Cumulonimbus.Request<
        { domain: string; allowsSubdomains: boolean },
        null,
        null
      >,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Domain>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          let invalidFields = getInvalidFields(req.body, {
            domain: "string",
            allowsSubdomains: "boolean",
          });

          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            try {
              if (await Domain.findOne({ where: { domain: req.body.domain } }))
                res
                  .status(409)
                  .json(new ResponseConstructors.Errors.DomainExists());
              else {
                let domain = await Domain.create({
                  domain: req.body.domain,
                  allowsSubdomains: req.body.allowsSubdomains,
                });

                res.status(201).json(domain.toJSON());
              }
            } catch (error) {
              throw error;
            }
          }
        }
      }
    },
  },
  {
    method: "patch",
    path: "/domain/:id",
    preHandlers: [Multer().none(), AutoTrim()],
    async handler(
      req: Cumulonimbus.Request<
        { allowsSubdomains: boolean },
        { id: string },
        null
      >,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Domain>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          let invalidFields = getInvalidFields(req.body, {
            allowsSubdomains: "boolean",
          });
          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            try {
              let domain = await Domain.findOne({
                where: {
                  domain: req.params.id,
                },
              });

              if (!domain)
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidDomain());
              else {
                let updatedDomain = await domain.update({
                  allowsSubdomains: req.body.allowsSubdomains,
                });

                res.status(200).json(updatedDomain.toJSON());
              }
            } catch (error) {
              throw error;
            }
          }
        }
      }
    },
  },
  {
    method: "delete",
    path: "/domain/:id",
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Domain>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            let domain = await Domain.findOne({
              where: {
                domain: req.params.id,
              },
            });

            if (!domain)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidDomain());
            else {
              let users = await User.findAll({
                where: {
                  domain: req.params.id,
                },
              });

              for (let user of users) {
                await user.update({ domain: "alekeagle.me", subdomain: null });
              }

              await domain.destroy();

              res.status(200).json(domain.toJSON());
            }
          } catch (error) {
            throw error;
          }
        }
      }
    },
  },
  {
    method: "delete",
    path: "/domains",
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<{ domains: string[] }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          if (
            !req.body.domains ||
            req.body.domains.length < 1 ||
            req.body.domains.length > 100
          )
            res
              .status(400)
              .json(new ResponseConstructors.Errors.MissingFields(["domains"]));
          else {
            let { count, rows: domains } = await Domain.findAndCountAll({
              where: {
                domain: {
                  [Op.in]: req.body.domains,
                },
              },
            });

            for (let domain of domains) {
              let users = await User.findAll({
                where: {
                  domain: domain.domain,
                },
              });

              for (let user of users) {
                await user.update({ domain: "alekeagle.me", subdomain: null });
              }
              await domain.destroy();
            }

            res.status(200).json({ count, type: "domain" });
          }
        }
      }
    },
  },
];

export default AdminDomainEndpoints;
