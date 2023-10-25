import { config } from 'dotenv';
(() => {
  // Set the default environment to production
  if (!process.env.ENV) {
    console.log('WARNING: No environment specified, defaulting to production.');
    process.env.ENV = 'production';
  }

  // Check if the environment is valid
  if (process.env.ENV !== 'development' && process.env.ENV !== 'production') {
    console.log('ERROR: Invalid environment specified. Exiting...');
    process.exit(1);
  }

  // Load the corresponding dotenv configuration file according to ENV
  config({ path: `./${process.env.ENV}.env` });
})();
