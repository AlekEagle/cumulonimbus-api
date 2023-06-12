import { config } from "dotenv";
(() => {
  // Set the default environment to production
  if (!process.env.ENV) process.env.ENV = "production";
  // Load the corresponding dotenv configuration file according to ENV
  config({ path: `./${process.env.ENV}.env` });
})();
