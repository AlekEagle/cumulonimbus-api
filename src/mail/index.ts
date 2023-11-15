import { logger } from '../index.js';

import { createTransport } from 'nodemailer';

// Create a SMTP transporter object
export let transport: ReturnType<typeof createTransport>;

export async function init(): Promise<boolean> {
  if (!transport) {
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

    logger.log('SMTP connection established successfully.');
    return true;
  }
  return false;
}

export default {
  init,
  transport,
};
