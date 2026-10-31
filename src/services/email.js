// ============================================================
// Nexus - Email Service Adapter
// SECURITY: Uses HTTP API (Resend) instead of raw SMTP to ensure 
// compatibility with Cloudflare Workers edge runtime.
// ============================================================

/**
 * Sends an email using the configured provider.
 * 
 * @param {Object} env - Cloudflare environment variables
 * @param {string} to - Recipient email address
 * @param {string} subject - Email subject
 * @param {string} htmlBody - Email content in HTML format
 */
export async function sendEmail(env, to, subject, htmlBody) {
  // SECURITY: Ensure the API key is configured before attempting to send
  if (!env.RESEND_API_KEY) {
    console.warn('[Email] RESEND_API_KEY is not set. Email will not be sent.');
    // In a dev environment, we might just log the code for testing
    return { success: false, error: 'Email provider not configured' };
  }

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'Nexus Auth <noreply@yourdomain.com>', // Configure this in env
        to: [to],
        subject: subject,
        html: htmlBody
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('[Email] Failed to send:', data);
      return { success: false, error: data.message };
    }

    return { success: true, id: data.id };
  } catch (e) {
    console.error('[Email] Network Error:', e);
    return { success: false, error: 'Network error while sending email' };
  }
}

/**
 * Generates a standardized verification email template.
 */
export function generateVerifyEmailHtml(code, siteName = 'Nexus') {
  // SECURITY: The code is strictly sanitized since it's just 6 digits.
  // Do not inject untrusted user input into HTML emails to prevent XSS.
  return `
    <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; background: #18181b; color: #e4e4e7; padding: 40px; border-radius: 12px;">
      <h2 style="color: #93c5fd; text-align: center;">${siteName}</h2>
      <p style="font-size: 16px;">Hello,</p>
      <p style="font-size: 16px;">You recently requested to verify your email address. Please use the following 6-digit code to complete the process:</p>
      
      <div style="text-align: center; margin: 30px 0;">
        <span style="display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 15px 25px; background: #27272a; border-radius: 8px; color: #ffffff;">
          ${code}
        </span>
      </div>
      
      <p style="font-size: 14px; color: #a1a1aa;">This code will expire in 15 minutes. If you did not request this, please ignore this email.</p>
      <hr style="border: none; border-top: 1px solid #3f3f46; margin: 30px 0;" />
      <p style="font-size: 12px; text-align: center; color: #71717a;">
        Powered by <a href="https://github.com/CrCLARE/Nexus" style="color: #60a5fa; text-decoration: none;">Nexus</a>
      </p>
    </div>
  `;
}
