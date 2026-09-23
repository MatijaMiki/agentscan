/* Cloudflare always publishes a project at <name>.pages.dev and there is no way
 * to turn that off, so the production copy would be a second, indexable origin
 * serving identical content. Send it to the real one.
 *
 * Only the bare production hostname is redirected: preview deployments live at
 * <hash>.ranwhat.pages.dev, and redirecting those would remove the ability to
 * check a branch before it ships.
 */
const PRODUCTION_PAGES_HOST = "ranwhat.pages.dev";
const CANONICAL_HOST = "ranwhat.com";

export const onRequest = ({ request, next }) => {
  const url = new URL(request.url);
  if (url.hostname === PRODUCTION_PAGES_HOST) {
    url.hostname = CANONICAL_HOST;
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }
  return next();
};
