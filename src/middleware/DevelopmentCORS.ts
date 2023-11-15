import { Request, Response, NextFunction } from 'express';

export default function (req: Request, res: Response, next: NextFunction) {
  if (process.env.ENV === 'development') {
    res.header('Access-Control-Allow-Origin', '*');
    res.header(
      'Access-Control-Allow-Headers',
      'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With,X-Session-Name',
    );
    res.header(
      'Access-Control-Expose-Headers',
      'X-RateLimit-Limit,X-RateLimit-Remaining,X-RateLimit-Reset,RateLimit-Limit,RateLimit-Remaining,RateLimit-Reset,Retry-After,Content-Length,Content-Range',
    );
    if (req.method === 'OPTIONS') {
      res.header(
        'Access-Control-Allow-Methods',
        'GET,HEAD,PUT,PATCH,POST,DELETE',
      );
      return res.status(204).send();
    }
  }
  res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  next();
}
