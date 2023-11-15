import { logger } from '../index.js';
import { transport, init } from './index.js';
import { generateVerifyEmailToken } from '../utils/Token.js';

await init();

export async function sendUpdateVerificationEmail(
  to: string,
  username: string,
): Promise<{ success: boolean; error?: string; token: string }> {
  const token = generateVerifyEmailToken(),
    url = `${
      process.env.ENV === 'development'
        ? 'http://localhost:5173'
        : 'https://alekeagle.me'
    }/verify?token=${token}`;

  try {
    await transport.sendMail({
      to,
      subject: 'Verify your new email address',
      html: `
      <h1>Verify your new email address</h1>
      <p>Hi ${username},</p>
      <p>Your email address was recently updated, please verify your new email address by clicking the link below.</p>
      <a href="${url}">Verify Account</a>
      <p>If you cannot click the link, please copy and paste the following URL into your browser:</p>
      <p>${url}</p>
      <p>This link will expire in 1 hour.</p>
      `,
    });
    return { success: true, token };
  } catch (err) {
    logger.error(err);
    return { success: false, error: err.message, token };
  }
}
