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

  // Test for required environment variables
  const requiredEnvVars = [
    'DATABASE_HOST',
    'DATABASE_PORT',
    'DATABASE_USER',
    'DATABASE_PASS',
    'DATABASE',
    'INSTANCE',
    'BASE_UPLOAD_PATH',
    'BASE_THUMBNAIL_PATH',
    'DEFAULT_DOMAIN',
    'WEBAUTHN_RPID',
    'TOKEN_ISSUERS',
    'FRONTEND_BASE_URL',
    'THUMBNAIL_BASE_URL',
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_USER',
    'SMTP_PASS',
    'SMTP_FROM',
  ];

  let missingEnvVars = [];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      missingEnvVars.push(envVar);
    }
  }

  if (missingEnvVars.length > 0) {
    console.log(
      `ERROR: Missing required environment variables: ${missingEnvVars.join(', ')}`,
    );
    process.exit(1);
  }
})();
