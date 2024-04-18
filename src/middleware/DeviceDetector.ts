const DeviceDetector = (await import('node-device-detector')).default;
const ClientHints = (await import('node-device-detector/client-hints.js'))
  .default;
import { Request, NextFunction, Response, RequestHandler } from 'express';

export default function (): RequestHandler {
  // @ts-ignore
  const detector = new DeviceDetector({
    clientIndexes: true,
    deviceIndexes: true,
  });
  // @ts-ignore
  const clientHints = new ClientHints();
  return (req: Request, res: Response, next: NextFunction) => {
    const hints = clientHints.parse(req.headers);
    req.useragent = detector.detect(req.headers['user-agent'], hints);
    next();
  };
}
