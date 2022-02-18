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
            if (req.query.limit > 50) req.query.limit = 50;
            let domains = await Domain.findAndCountAll({
                limit: req.query.limit,
                offset: req.query.offset,
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
