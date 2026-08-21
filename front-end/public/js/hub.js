/**
 * CyberHub home page bootstrap.
 *
 * This used to render a grid of module cards. The professors pointed out that
 * every module on it is already in the left sidebar, so the landing page spent
 * its first screen repeating navigation the user had just walked past. The
 * cards are gone; HubCourses owns what replaced them.
 *
 * What stays here is the page's auth gate and shell wiring — initHub() is the
 * only thing standing between an unauthenticated visitor and /hub.
 */

async function initHub() {
  // Auth check
  const authed = await Auth.requireAuth();
  if (!authed) return;

  const user = Auth.getUser();

  // SINGLE owner of the greeting. loadSiteConfig() in hub.html used to
  // overwrite this with "Welcome to {site_name}" a moment later and usually
  // won the race, so the personalisation almost never survived. The site name
  // lives in the header and document.title, which is where it belongs.
  const welcome = document.getElementById('welcomeTitle');
  if (welcome) {
    welcome.textContent = user?.firstName ? `Welcome back, ${user.firstName}` : 'Welcome back';
  }
  document.getElementById('headerUser').textContent = user?.email || '';

  // Init sidebar — this is what still lists the modules.
  Layout.init();

  if (typeof HubCourses !== 'undefined') HubCourses.init();
  if (typeof HubCourses !== 'undefined') HubCourses.renderWorkspaces();
}

document.addEventListener('DOMContentLoaded', initHub);
