// src/utils/email.js

export const RESET_TOKEN_TTL = 1000 * 60 * 60; // 1 hour

const RESET_EMAIL_HTML = `<!DOCTYPE html>
<html>
  <head><meta charset="UTF-8"/><title>Password Reset</title></head>
  <body style="font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0">
    <div style="max-width:600px;margin:2rem auto;background:#fff;padding:1.5rem;border-radius:8px">
      <h1 style="color:#333">Password Reset Request</h1>
      <p>We got a request to reset your aibarf.com password. Click below:</p>
      <p style="text-align:center">
        <a href="{{RESET_LINK}}" 
           style="display:inline-block;padding:.75rem 1.5rem;
                  background:#2b7dfc;color:#fff;text-decoration:none;
                  border-radius:4px;font-weight:bold">
          Reset My Password
        </a>
      </p>
      <p>If that button fails, copy & paste:</p>
      <p><a href="{{RESET_LINK}}">{{RESET_LINK}}</a></p>
      <p>If you didn’t ask, ignore this email.</p>
      <p style="font-size:.8rem;color:#999;text-align:center;margin-top:2rem">
        &copy; 2025 aibarf LLC
      </p>
    </div>
  </body>
</html>`;

const RESET_EMAIL_TEXT = `Password Reset Request

We got a request to reset your aibarf.com password.

Reset link: {{RESET_LINK}}

If you didn’t ask, you can ignore this email.

© 2025 aibarf LLC
`;

export async function sendResetEmail(env, toEmail, token) {
  const resetLink = `https://aibarf.com/reset-password.html?token=${token}`;
  const htmlBody = RESET_EMAIL_HTML.replace(/{{RESET_LINK}}/g, resetLink);
  const textBody = RESET_EMAIL_TEXT.replace(/{{RESET_LINK}}/g, resetLink);
  const auth = btoa(`api:${env.MAILGUN_API_KEY}`);

  const res = await fetch('https://api.mailgun.net/v3/mg.aibarf.com/messages', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      from: 'no-reply@mg.aibarf.com',
      to: toEmail,
      subject: 'Reset your aibarf.com password',
      text: textBody,
      html: htmlBody,
    }),
  });

  if (!res.ok) throw new Error('Mailgun failed: ' + (await res.text()));
}
