import { logger } from '../index.js';
import { transport, init } from './index.js';

await init();

export async function sendBannedNotice(
  to: string,
  username: string,
  reason: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    await transport!.sendMail({
      to,
      subject: 'Your Cumulonimbus account has been banned',
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
    <h1>${username},</h1>
    <p>Your Cumulonimbus account has been banned.</p>

    <div class="divider"></div>

    <h1>Why was my account banned?</h1>
    <p>
      Your account was banned due to a violation of our
      <a href="https://alekeagle.me/tos" target="_blank" rel="noreferrer"
        >terms of service</a
      >. The reason provided is as follows:
    </p>
    <p><strong>${reason}</strong></p>

    <div class="divider"></div>

    <h1>What does this mean?</h1>
    <p>
      This means that you are no longer able to login to your account. Uploaded
      content is still accessible, but you are unable to modify, delete, or
      upload new content.
    </p>

    <div class="divider"></div>

    <h1>What can I do?</h1>
    <p>
      If you believe this was a mistake, please contact us at
      <a href="mailto:appeals@alekeagle.me">appeals@alekeagle.me</a>
      to submit an appeal. Please provide as much information as possible to
      help us understand your situation.
    </p>

    <footer>
      This email was sent to "${to}" with important account information. This
      important system message can not be unsubscribed from.
    </footer>
  </body>
</html>`.trim(),
    });
    return { success: true };
  } catch (err) {
    logger.error(err);
    return { success: false, error: err.message };
  }
}
