/* POST /api/contact
 *
 * Verifies the Turnstile token server-side, then emails the message to the
 * address verified in Email Routing. Cloudflare's send_email binding can only
 * deliver to addresses already verified on this account, which is exactly the
 * shape a contact form needs and means no third-party mail service, no API key
 * and nothing leaving Cloudflare.
 *
 * This is a Worker rather than a Pages Function because send_email is not
 * among the bindings Pages Functions can hold. It is routed onto
 * ranwhat.com/api/* so the browser still sees one origin and needs no CORS.
 *
 * A Turnstile token that is never verified is decoration. This is the call that
 * makes the widget mean anything.
 */
import { EmailMessage } from "cloudflare:email";

const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TO = "ranwhatcom@gmail.com";
const FROM = "form@ranwhat.com";

const SUBJECTS = {
  plus: "ranwhat Plus",
  team: "ranwhat Team",
  bug: "ranwhat: something the tool got wrong",
  other: "ranwhat enquiry",
};

const LIMITS = { message: 8000, email: 200 };

const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

/* Header injection: a newline in a header value lets someone append headers of
   their own, e.g. a Bcc. Strip CR and LF from anything that lands in one. */
const header = (s) => String(s || "").replace(/[\r\n]+/g, " ").trim();

async function handleContact(request, env) {
  let form;
  try {
    form = await request.json();
  } catch {
    return json(400, { error: "Expected JSON." });
  }

  const token = form["cf-turnstile-response"];
  if (!token) return json(400, { error: "Complete the challenge and try again." });

  const verify = await fetch(SITEVERIFY, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET,
      response: token,
      remoteip: request.headers.get("cf-connecting-ip") || undefined,
    }),
  });
  const outcome = await verify.json();
  if (!outcome.success) {
    return json(403, { error: "That challenge did not verify. Reload and try again." });
  }

  const topic = SUBJECTS[form.about] ? form.about : "other";
  const message = String(form.message || "").trim();
  const replyTo = header(form.email).slice(0, LIMITS.email);

  if (!message) return json(400, { error: "The message is empty." });
  if (message.length > LIMITS.message) {
    return json(400, { error: "That message is longer than this form accepts." });
  }
  if (!replyTo || !/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(replyTo)) {
    return json(400, { error: "That email address does not look right." });
  }

  const body = [
    message,
    "",
    "--",
    `about: ${topic}`,
    `from:  ${replyTo}`,
  ].join("\r\n");

  /* The envelope has to come from this domain for SPF and DKIM to align, so
     the writer's address goes in the display name and the subject instead.
     Otherwise every submission looks identical in a mailbox list and you have
     to open it to find out who wrote in. Both values are run through header()
     first: a newline in either would let someone append headers of their own. */
  const raw = [
    `From: ${header(replyTo)} via ranwhat.com <${FROM}>`,
    `To: <${TO}>`,
    `Reply-To: <${replyTo}>`,
    `Subject: ${header(SUBJECTS[topic])} \u00b7 ${header(replyTo)}`,
    `Message-ID: <${crypto.randomUUID()}@ranwhat.com>`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="utf-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    body,
  ].join("\r\n");

  try {
    await env.CONTACT_EMAIL.send(new EmailMessage(FROM, TO, raw));
  } catch (err) {
    /* Say it failed rather than showing a success page over a lost message. */
    return json(502, { error: "The message could not be sent. Write to hello@ranwhat.com instead." });
  }

  return json(200, { ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/api/contact") return json(404, { error: "Not found." });
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "POST only." }), {
        status: 405,
        headers: { "content-type": "application/json; charset=utf-8", allow: "POST" },
      });
    }
    return handleContact(request, env);
  },
};
