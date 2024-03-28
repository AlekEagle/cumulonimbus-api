import { logger } from '../index.js';
import { transport, init } from './index.js';
import {
  generateEmailVerificationToken,
  TokenStructure,
} from '../utils/Token.js';

await init();

export default async function sendVerificationEmail(
  to: string,
  username: string,
): Promise<{
  success: boolean;
  error?: string;
  token?: string;
  tokenData?: TokenStructure;
}> {
  const { token, data } = await generateEmailVerificationToken(to),
    url = `${
      process.env.ENV === 'development'
        ? 'http://localhost:5173'
        : 'https://alekeagle.me'
    }/verify?token=${token}`;

  try {
    await transport.sendMail({
      to,
      subject: 'Verify your Cumulonimbus account email',
      html: `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      :root {
        font-family: Arial, sans-serif;
      }
      p {
        font-size: 1.2rem;
      }

      div.divider {
        margin: 20px 0;
        border-bottom: 1px solid #000;
      }

      footer {
        margin-top: 80px;
        font-size: 0.8rem;
      }
    </style>
  </head>
  <body>
    <h1>Hi ${username}!</h1>
    <p>Before you can start uploading files, you'll need to verify your email address.</p>

    <div class="divider"></div>

    <a href="${url}" target="_blank" rel="noreferrer">
      <button style="padding: 10px 20px; font-size: 1.2rem; cursor: pointer;">
        Verify your email
      </button>
    </a>

    <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
    <p>${url}</p>
    
    <footer>
      This email was sent to "${to}" with important account information. This
      important system message can not be unsubscribed from.
    </footer>
  </body>
</html>`.trim(),
    });
    return { success: true, token, tokenData: data };
  } catch (err) {
    logger.error(err);
    return { success: false, error: err.message };
  }
}
