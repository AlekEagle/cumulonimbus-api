import logger from '../utils/LogMachine.js';
import { transport, init } from './index.js';
import type User from '../DB/User.js';

await init();

export async function sendFilesDeletionSuccessEmail(
  user: User,
  staffInitiated: boolean = false,
): Promise<{ success: boolean; error?: Error }> {
  try {
    await transport!.sendMail({
      to: user.email,
      subject: 'Cumulonimbus All Files Deletion Complete',
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
      We just wanted to let you know that we finished deleting all files from your Cumulonimbus
      account.
    </p>
    ${staffInitiated ? `<p>This deletion was initiated by a staff member.</p>` : ''}
    <footer>
      This email was sent to "${user.email}" because ${staffInitiated ? 'a staff member' : 'you'} requested the deletion of your
      Cumulonimbus files.
    </footer>
  </body>
</html>`,
    });
    return { success: true };
  } catch (error) {
    logger.error('Failed to send files deletion success email', error);
    return { success: false, error: error as Error };
  }
}
