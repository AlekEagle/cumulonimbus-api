import { logger, app } from '../index.js';
import { Errors } from '../utils/TemplateResponses.js';

logger.debug('Route importer invoked! Routes are being imported...');

// Import routes
await import('./account.js');
await import('./domain.js');
await import('./file.js');
await import('./instruction.js');
await import('./session.js');
await import('./upload.js');

app.all('*', (req, res) => {
  logger.warn(`A request was made to an invalid endpoint: ${req.path}`);
  res.status(404).send(new Errors.InvalidEndpoint());
});

logger.debug('Loaded catch-all 404 route.');
