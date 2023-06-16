import { Cumulonimbus } from "../../types";
import { Sequelize } from "sequelize";
import Multer from "multer";
import Bcrypt from "bcrypt";
import User from "../../utils/DB/User";
import ExpressRateLimits from "express-rate-limit";
import ms from "ms";
import Express from "express";
import {
  sessionName,
  getInvalidFields,
  FieldTypeOptions,
  ResponseConstructors,
  validateSubdomain,
} from "../../utils/RequestUtils";
import { generateToken } from "../../utils/Token";
import { randomInt } from "crypto";
import { unlink } from "fs/promises";
import File from "../../utils/DB/File";
import Domain from "../../utils/DB/Domain";
import { existsSync } from "node:fs";
import { usernameRegex } from "../..";
import AutoTrim from "../../utils/AutoTrim";

const UserAccountEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: "get",
    path: "/user",
    async handler(
      req,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        let u = req.user.toJSON();
        delete u.password;
        delete u.sessions;
        res.status(200).json(u as Cumulonimbus.Structures.User);
      }
    },
  },
  {
    method: "patch",
    path: "/user",
    preHandlers: [Multer().none(), AutoTrim(["password", "newPassword"])],
    async handler(
      req: Cumulonimbus.Request<{
        username: string;
        email: string;
        newPassword: string;
        password: string;
      }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        let invalidFields = getInvalidFields(req.body, {
          username: new FieldTypeOptions("string", true),
          email: new FieldTypeOptions("string", true),
          newPassword: new FieldTypeOptions("string", true),
          password: "string",
        });
        if (
          req.body.username &&
          !req.body.username.match(usernameRegex) &&
          !invalidFields.includes("username")
        ) {
          invalidFields.push("username");
        }
        if (invalidFields.length > 0)
          res
            .status(400)
            .json(new ResponseConstructors.Errors.MissingFields(invalidFields));
        else if (
          req.body.username === undefined &&
          req.body.email === undefined &&
          req.body.newPassword === undefined
        )
          res
            .status(400)
            .json(
              new ResponseConstructors.Errors.MissingFields([
                "username",
                "email",
                "password",
              ])
            );
        else {
          try {
            let match = await Bcrypt.compare(
              req.body.password,
              req.user.password
            );
            if (!match)
              res
                .status(401)
                .json(new ResponseConstructors.Errors.InvalidPassword());
            else {
              try {
                let newFields: { [key: string]: string } = {};
                if (req.body.newPassword)
                  newFields["password"] = await Bcrypt.hash(
                    req.body.newPassword,
                    randomInt(0, 15)
                  );
                if (req.body.username) {
                  newFields["username"] = req.body.username;
                }
                if (req.body.email) newFields["email"] = req.body.email;

                await req.user.update(newFields);
                let u = req.user.toJSON();
                delete u.password;
                delete u.sessions;
                res.status(200).json(u as Cumulonimbus.Structures.User);
              } catch (error) {
                throw error;
              }
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
    path: "/user",
    preHandlers: [Multer().none(), AutoTrim(["password"])],
    async handler(
      req: Cumulonimbus.Request<{ username: string; password: string }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let invalidFields = getInvalidFields(req.body, {
            username: "string",
            password: "string",
          });
          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            let match = await Bcrypt.compare(
              req.body.password,
              req.user.password
            );
            if (!match)
              res
                .status(401)
                .json(new ResponseConstructors.Errors.InvalidPassword());
            if (
              req.body.username.toLowerCase() !==
              req.user.username.toLowerCase()
            )
              res
                .status(401)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              let uls = await File.findAll({
                where: Sequelize.where(Sequelize.col("userID"), req.user.id),
              });
              for (let ul of uls) {
                try {
                  await unlink(`/var/www-uploads/${ul.filename}`);
                  if (
                    existsSync(
                      `/tmp/cumulonimbus-preview-cache/${ul.filename}.webp`
                    )
                  )
                    await unlink(
                      `/tmp/cumulonimbus-preview-cache/${ul.filename}.webp`
                    );
                  await ul.destroy();
                } catch (error) {
                  throw error;
                }
              }
              let strippedUser = req.user.toJSON();
              delete strippedUser.password;
              delete strippedUser.sessions;
              req.user.destroy();
              res
                .status(200)
                .json(strippedUser as Cumulonimbus.Structures.User);
            }
          }
        }
      } catch (error) {
        throw error;
      }
    },
  },
  {
    method: "post",
    path: "/user",
    preHandlers: [
      Multer().none(),
      ExpressRateLimits({
        windowMs: ms("30mins"),
        max: 1,
        keyGenerator: (req: Cumulonimbus.Request, res: Express.Response) => {
          return req.user
            ? req.user.id
            : (Array.isArray(req.headers["x-forwarded-for"])
                ? req.headers["x-forwarded-for"][0]
                : req.headers["x-forwarded-for"]) || req.ip;
        },
        handler(
          req: Express.Request,
          res: Express.Response,
          next: Express.NextFunction
        ) {
          res.status(429).send(new ResponseConstructors.Errors.RateLimited());
        },
        skipFailedRequests: true,
      }),
      AutoTrim(["password", "repeatPassword"]),
    ],
    async handler(
      req: Cumulonimbus.Request<{
        username: string;
        email: string;
        password: string;
        repeatPassword: string;
        rememberMe: boolean;
      }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.SuccessfulAuth>
    ) {
      try {
        let invalidFields = getInvalidFields(req.body, {
          username: "string",
          email: "string",
          password: "string",
          repeatPassword: "string",
          rememberMe: new FieldTypeOptions("boolean", true),
        });
        if (
          (!req.body.username || !req.body.username.match(usernameRegex)) &&
          !invalidFields.includes("username")
        ) {
          invalidFields.push("username");
        }
        if (invalidFields.length > 0)
          res
            .status(400)
            .json(new ResponseConstructors.Errors.MissingFields(invalidFields));
        else {
          let u = await User.findOne({
            where: Sequelize.or(
              Sequelize.where(
                Sequelize.fn("lower", Sequelize.col("username")),
                Sequelize.fn("lower", req.body.username)
              ),
              Sequelize.where(
                Sequelize.fn("lower", Sequelize.col("email")),
                Sequelize.fn("lower", req.body.email)
              )
            ),
          });
          if (u)
            res.status(409).json(new ResponseConstructors.Errors.UserExists());
          else {
            if (req.body.password !== req.body.repeatPassword)
              res
                .status(400)
                .json(new ResponseConstructors.Errors.InvalidPassword());
            else {
              try {
                let userID = Date.now().toString(),
                  newHash = await Bcrypt.hash(
                    req.body.password,
                    randomInt(0, 15)
                  ),
                  token = await generateToken(
                    userID,
                    sessionName(req),
                    !req.body.rememberMe
                  );
                await User.create({
                  username: req.body.username,
                  email: req.body.email,
                  domain: "alekeagle.me",
                  subdomain: "",
                  password: newHash,
                  id: userID,
                  sessions: [
                    {
                      iat: token.data.payload.iat,
                      exp: token.data.payload.exp,
                      name: token.data.payload.name,
                    },
                  ],
                });
                res.status(201).json({
                  token: token.token,
                  exp: token.data.payload.exp,
                } as Cumulonimbus.Structures.SuccessfulAuth);
              } catch (error) {
                throw error;
              }
            }
          }
        }
      } catch (error) {
        throw error;
      }
    },
  },
  {
    method: "patch",
    path: "/user/domain",
    preHandlers: [Multer().none(), AutoTrim()],
    async handler(
      req: Cumulonimbus.Request<{ domain: string; subdomain?: string }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let invalidFields = getInvalidFields(req.body, {
            domain: "string",
            subdomain: new FieldTypeOptions("string", true),
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
                  domain: req.body.domain,
                },
              });
              if (!domain)
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidDomain());
              else {
                if (!req.body.subdomain) {
                  await req.user.update({
                    domain: domain.domain,
                    subdomain: null,
                  });

                  let u = req.user.toJSON();
                  delete u.password;
                  delete u.sessions;
                  res.status(200).json(u as Cumulonimbus.Structures.User);
                } else {
                  if (!domain.allowsSubdomains)
                    res
                      .status(400)
                      .json(
                        new ResponseConstructors.Errors.SubdomainNotSupported()
                      );
                  else {
                    let safeSubdomain = validateSubdomain(req.body.subdomain);
                    if (safeSubdomain.length > 63)
                      res
                        .status(400)
                        .json(
                          new ResponseConstructors.Errors.InvalidSubdomain(
                            safeSubdomain
                          )
                        );
                    else {
                      await req.user.update({
                        domain: domain.domain,
                        subdomain: safeSubdomain,
                      });

                      let u = req.user.toJSON();
                      delete u.password;
                      delete u.sessions;
                      res.status(200).json(u as Cumulonimbus.Structures.User);
                    }
                  }
                }
              }
            } catch (error) {
              throw error;
            }
          }
        }
      } catch (error) {
        throw error;
      }
    },
  },
];

export default UserAccountEndpoints;
