import { logger } from "../index.js";

logger.log("Route importer invoked! Routes are being imported...");

import("./unprivileged/account.js");
import("./unprivileged/domain.js");
import("./unprivileged/file.js");
import("./unprivileged/instruction.js");
import("./unprivileged/session.js");

import("./privileged/account.js");
import("./privileged/domain.js");
import("./privileged/file.js");
import("./privileged/instruction.js");
