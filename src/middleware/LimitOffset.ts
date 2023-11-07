import { RequestHandler } from 'express';

export default function LimitOffset(
  min: number,
  max: number,
  defaultLimit: number = 50,
): RequestHandler {
  return (req, res, next) => {
    req.limit =
      req.query.limit &&
      parseInt(req.query.limit as string) >= min &&
      parseInt(req.query.limit as string) <= max
        ? parseInt(req.query.limit as string)
        : defaultLimit;
    req.offset =
      req.query.offset && parseInt(req.query.offset as string) >= 0
        ? parseInt(req.query.offset as string)
        : 0;
    next();
  };
}
