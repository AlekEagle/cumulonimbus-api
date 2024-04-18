import { logger } from '../index.js';

import { createTransport } from 'nodemailer';

// Create a SMTP transporter object
export let transport: ReturnType<typeof createTransport> | null = null;

export async function init(): Promise<boolean> {
  if (!transport) {
    logger.info('Initializing SMTP transport...');
    logger.debug(
      `Connecting to ${process.env.SMTP_HOST}:${process.env.SMTP_PORT}...`,
    );
    transport = createTransport(
      {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: false,
        ignoreTLS: true,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      },
      {
        from: 'Cumulonimbus <no-reply@alekeagle.me>',
      },
    );

    try {
      await transport.verify();
    } catch (err) {
      console.error(err);
      return false;
    }

    logger.info('SMTP connection established successfully.');
    return true;
  }
  return false;
}

export default {
  init,
  transport,
};
