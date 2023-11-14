import { logger } from '../index.js';
import { transport, init } from './index.js';

await init();

export async function sendBannedNotice(
  to: string,
  username: string,
  reason: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    await transport.sendMail({
      to,
      subject: 'Your Cumulonimbus account has been banned',
      html: `
      <h1>Your Cumulonimbus account has been banned</h1>
      <p>Hi ${username},</p>
      <p>Your account has been banned for the following reason:</p>
      <p><strong>${reason}</strong></p>
      <p>If you believe this is a mistake, please contact us at <a href="mailto:appeals@alekeagle.me">appeals@alekeagle.me</a>.</p>
      `,
    });
    return { success: true };
  } catch (err) {
    logger.error(err);
    return { success: false, error: err.message };
  }
}
