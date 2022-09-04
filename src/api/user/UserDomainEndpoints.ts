import { ResponseConstructors } from '../../utils/RequestUtils';
import { Cumulonimbus } from '../../types';
import Domain from '../../utils/DB/Domain';

const UserDomainEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/domains',
    async handler(
      req: Cumulonimbus.Request<null, null, { limit: number; offset: number }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.Domain>
      >
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          try {
            const limit = req.query.limit && req.query.limit <= 50 && req.query.limit > 0 ? req.query.limit : 50,
                  offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
            let domains = await Domain.findAndCountAll({
                limit,
                offset,
                order: [['createdAt', 'DESC']]
              }),
              rows = domains.rows.map(d => d.toJSON());

            res.status(200).json({ count: domains.count, items: rows });
          } catch (error) {
            throw error;
          }
        }
      } catch (error) {
        throw error;
      }
    }
  },
  {
    method: 'get',
    path: '/domains/slim',
    async handler(
      req: Cumulonimbus.Request<null, null, null>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.DomainSlim>
      >
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          try {
            let domains = await Domain.findAndCountAll({
                order: [['createdAt', 'DESC']]
              }),
              rows = domains.rows.map(d => {
                let a = d.toJSON();
                return {
                  domain: a.domain,
                  allowsSubdomains: a.allowsSubdomains
                };
              });

            res.status(200).json({ count: domains.count, items: rows });
          } catch (error) {
            throw error;
          }
        }
      } catch (error) {
        throw error;
      }
    }
  },
  {
    method: 'get',
    path: '/domain/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Domain>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          try {
            let domain = await Domain.findOne({
              where: {
                domain: req.params.id
              }
            });

            res.status(200).json(domain.toJSON());
          } catch (error) {
            throw error;
          }
        }
      } catch (error) {
        throw error;
      }
    }
  }
];

export default UserDomainEndpoints;
