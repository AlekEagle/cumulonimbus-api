import { logger, app } from "../index.js";
import { Errors } from "../utils/TemplateResponses.js";

logger.log("Route importer invoked! Routes are being imported...");

await import("./unprivileged/account.js");
await import("./unprivileged/domain.js");
await import("./unprivileged/file.js");
await import("./unprivileged/instruction.js");
await import("./unprivileged/session.js");
await import("./unprivileged/upload.js");

await import("./privileged/account.js");
await import("./privileged/domain.js");
await import("./privileged/file.js");
await import("./privileged/instruction.js");
await import("./privileged/session.js");

app.all("*", (req, res) => {
  logger.warn(`A request was made to an invalid endpoint: ${req.path}`);
  res.status(404).send(new Errors.InvalidEndpoint());
});

logger.log("Loaded catch-all 404 route.");
