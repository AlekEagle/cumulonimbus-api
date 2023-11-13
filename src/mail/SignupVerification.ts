import { logger } from '../index.js';
import { transport, init } from './index.js';
import { randomInt } from 'crypto';
import { EMAIL_VERIFICATION_TOKEN_LENGTH } from '../utils/Constants.js';

await init();

function generateToken() {
  return Buffer.from(
    new Array(EMAIL_VERIFICATION_TOKEN_LENGTH)
      .fill(0)
      .map((_) => randomInt(0, 255)),
  ).toString('base64');
}

export async function sendSignupVerificationEmail(
  to: string,
  username: string,
): Promise<{ success: boolean; error?: string; token: string }> {
  const token = generateToken(),
    url = `${
      process.env.ENV === 'development'
        ? 'http://localhost:5173'
        : 'https://alekeagle.me`'
    }/verify?token=${token}`;

  try {
    await transport.sendMail({
      to,
      subject: 'Verify your Cumulonimbus account',
      html: `
      <h1>Verify your Cumulonimbus account</h1>
      <p>Hi ${username},</p>
      <p>Thanks for signing up for Cumulonimbus! Please click the link below to verify your account.</p>
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
