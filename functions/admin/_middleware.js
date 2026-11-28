import {ADMIN_URLS, urlJoin} from "../../common-src/StringUtils";
import {getCookie, verifySessionCookie, SESSION_COOKIE} from "../../common-src/GoogleAuth";
import FeedDb, {getFetchItemsParams} from "../../edge-src/models/FeedDb";
import OnboardingChecker from "../../common-src/OnboardingUtils";
import {STATUSES} from "../../common-src/Constants";

// Google sign-in: the admin is open only with a valid session cookie
// (set by /admin/auth/callback after Google verifies the account).
// This replaces the old HTTP Basic Auth password lock, which browsers
// cache with no way to log out. The login/logout pages themselves
// are exempt so the flow can run.
async function requireGoogleSession({request, env, next}) {
  const urlObj = new URL(request.url);
  if (urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/auth/'))) {
    return next();
  }
  const email = await verifySessionCookie(env, getCookie(request, SESSION_COOKIE));
  if (email) {
    return next();
  }
  return Response.redirect(`${urlObj.origin}/admin/auth/login`, 302);
}

async function fetchFeed({request, next, env, data}) {
  const urlObj = new URL(request.url);

  if (urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/auth/'))) {
    return next();
  }

  if (urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/ajax/'))) {
    return next();
  }

  let fetchItems = null;
  if (urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/feed/json')) ||
      urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/items/list'))) {
    fetchItems = getFetchItemsParams(request, {
      'status__!=': STATUSES.DELETED,
    });
  } else if (urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/items/'))) {
    // Either /items/ or /items/{id}
    if (!urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/items/new'))) {
      return next();
    }
  } else if (urlObj.pathname.startsWith(urlJoin(ADMIN_URLS.home(), '/settings/code-editor'))) {
    fetchItems = getFetchItemsParams(request, {
      'status__!=': STATUSES.DELETED,
    }, 1);
  }

  const feedDb = new FeedDb(env, request);
  const contentFromDb = await feedDb.getContent(fetchItems)

  const onboardingChecker = new OnboardingChecker(contentFromDb, request, env);
  const onboardingResult = onboardingChecker.getResult();

  data.feedDb = feedDb;
  data.feedContent = contentFromDb;
  data.onboardingResult = onboardingResult;

  return next();
}

export const onRequest = [requireGoogleSession, fetchFeed];
