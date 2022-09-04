import { Cumulonimbus } from '../../types';
import Instruction from '../../utils/DB/Instruction';
import { ResponseConstructors } from '../../utils/RequestUtils';

const UserInstructionEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/instructions',
    async handler(
      req: Cumulonimbus.Request<null, null, { limit: number; offset: number }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.Instruction>
      >
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        try {
          const limit = req.query.limit && req.query.limit <= 50 && req.query.limit > 0 ? req.query.limit : 50,
                offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
          let { count, rows: instructions } = await Instruction.findAndCountAll(
            {
              limit,
              offset
            }
          );

          let items = instructions.map(i => i.toJSON());

          res.status(200).json({ count, items });
        } catch (error) {
          throw error;
        }
      }
    }
  },
  {
    method: 'get',
    path: '/instruction/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<null>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        try {
          let instruction = await Instruction.findOne({
            where: {
              name: req.params.id
            }
          });
          if (!instruction)
            res
              .status(404)
              .json(new ResponseConstructors.Errors.InvalidInstruction());
          else {
            res.status(200).json(instruction.toJSON());
          }
        } catch (error) {
          throw error;
        }
      }
    }
  }
];

export default UserInstructionEndpoints;
