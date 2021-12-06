import { ResponseStructures } from '../utils/ResponseStructures';
import { Cumulonimbus } from '../types';
import { Op } from 'sequelize/dist';
import { unlink } from 'fs/promises';
import Upload from '../utils/DB/Upload';

const FileEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/files',
    async handler(req, res) {
      if (!req.user)
        res.status(401).json(new ResponseStructures.NotAuthenticated());
    }
  }
];
