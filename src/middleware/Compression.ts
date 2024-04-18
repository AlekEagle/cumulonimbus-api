import compression, { filter } from 'compression';
import { RequestHandler } from 'express';

export default function Compression(): RequestHandler {
  return compression({
    filter: (req, res) => {
      if (req.headers['x-no-compression']) return false;
      return filter(req, res);
    },
  });
}
