/* Everything that is not the canonical hostname is sent to it.
 *
 * Cloudflare always publishes a project at <name>.pages.dev and that cannot be
 * turned off, so without this it is a second indexable origin serving
 * identical content. www is the same problem with a longer history: every page
 * already declares <link rel="canonical"> without it, so the redirect just
 * makes the HTTP layer agree with the HTML.
 *
 * Preview deployments at <hash>.ranwhat.pages.dev are deliberately left alone,
 * since redirecting those would remove the ability to check a branch before it
 * ships.
 */
const CANONICAL_HOST = "ranwhat.com";
const REDIRECT_FROM = new Set(["ranwhat.pages.dev", "www.ranwhat.com"]);

export const onRequest = ({ request, next }) => {
  const url = new URL(request.url);
  if (REDIRECT_FROM.has(url.hostname)) {
    url.hostname = CANONICAL_HOST;
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }
  return next();
};
