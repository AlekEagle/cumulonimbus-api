import { Request, Response, NextFunction } from 'express';

export default function (req: Request, res: Response, next: NextFunction) {
  if (process.env.ENV === 'development') {
    res.header('Access-Control-Allow-Origin', '*');
    res.header(
      'Access-Control-Allow-Headers',
      'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Token-Name',
    );
    if (req.method === 'OPTIONS') {
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
      return res.status(204).send();
    }
  }
  res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  next();
}
