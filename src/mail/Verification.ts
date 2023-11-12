import { logger } from '../index.js';
import { transport, init } from './index.js';
import { randomInt } from 'crypto';

await init();

function generateToken() {
  return Buffer.from(
    new Array(96).fill(0).map((_) => randomInt(0, 255)),
  ).toString('base64');
}

export async function sendVerificationEmail(
  to: string,
  username: string,
): Promise<{ success: boolean; error?: string; token: string }> {
  const token = generateToken(),
    url = `https://alekeagle.me/verify?token=${token}`;

  try {
    await transport.sendMail({
      to,
      subject: 'Verify your Cumulonimbus account',
      text: `Hello ${username},\n\nPlease verify your account by clicking the following link:\n${url}\n\nIf you did not request this, please ignore this email.`,
      html: `<p>Hello ${username},</p><p>Please verify your account by clicking the following link:</p><p><a href="${url}">${url}</a></p><p>If you did not request this, please ignore this email.</p>`,
    });
    return { success: true, token };
  } catch (err) {
    logger.error(err);
    return { success: false, error: err.message, token };
  }
}
