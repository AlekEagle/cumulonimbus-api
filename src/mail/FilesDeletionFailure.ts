import logger from '../utils/LogMachine.js';
import { transport, init } from './index.js';
import type User from '../DB/User.js';

await init();

export async function sendFilesDeletionFailureEmail(
  user: User,
  staff?: User,
): Promise<{ success: boolean; error?: Error }> {
  try {
    if (!staff) {
      await transport!.sendMail({
        to: user.email,
        subject: 'Cumulonimbus All Files Deletion Failure',
        html: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      :root {
        font-family: Arial, sans-serif;
      }
      p {
        font-size: 1.2em;
      }

      footer {
        margin-top: 80px;
        font-size: 0.8rem;
      }
    </style>
  </head>
  <body>
    <p>Hi ${user.username},</p>
    <p>
      We attempted to delete all files from your Cumulonimbus account,
      but the process failed. Because the automated files deletion process
      failed, we've sent an alert to our team so that they can carry out a
      manual deletion of your files. You will receive another email once the
      manual deletion is completed in approximately 24-48 hours.
    </p>
    <footer>
      This email was sent to "${user.email}" because you requested the deletion
      of your Cumulonimbus files.
    </footer>
  </body>
</html>`,
      });
    }
    await transport!.sendMail({
      to: process.env.SMTP_USER, // The SMTP_USER is likely to be the email address of the system administrator
      subject: 'Cumulonimbus Files Deletion Failure Alert',
      html: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      :root {
        font-family: Arial, sans-serif;
      }
      p {
        font-size: 1.2em;
      }

      footer {
        margin-top: 80px;
        font-size: 0.8rem;
      }
    </style>
  </head>
  <body>
    <p>Hi,</p>
    <p>
      The automated files deletion process for the following user has failed:
    </p>
    <p><strong>${user.id} (${user.email})</strong></p>
    <footer>This is an automated alert from the Cumulonimbus system.</footer>
  </body>
</html>`,
    });
    return { success: true };
  } catch (error) {
    logger.error('Failed to send files deletion failure email', error);
    return { success: false, error: error as Error };
  }
}
