import {ADMIN_URLS, urlJoin} from "../../common-src/StringUtils";
import FeedDb, {getFetchItemsParams} from "../../edge-src/models/FeedDb";
import OnboardingChecker from "../../common-src/OnboardingUtils";
import {STATUSES} from "../../common-src/Constants";

async function requireAdminPassword({request, env, next}) {
  const expected = env.ADMIN_PASSWORD || '';
  const auth = request.headers.get('Authorization') || '';
  if (expected && auth.startsWith('Basic ')) {
    let decoded = '';
    try {
      decoded = atob(auth.slice(6));
    } catch (e) {
      decoded = '';
    }
    // Credential format is "admin:<password>"; compare in constant time.
    const candidate = `admin:${expected}`;
    if (decoded.length === candidate.length) {
      let diff = 0;
      for (let i = 0; i < decoded.length; i++) {
        diff |= decoded.charCodeAt(i) ^ candidate.charCodeAt(i);
      }
      if (diff === 0) {
        return next();
      }
    }
  }
  return new Response('Unauthorized', {
    status: 401,
    headers: {'WWW-Authenticate': 'Basic realm="mf admin", charset="UTF-8"'},
  });
}

async function fetchFeed({request, next, env, data}) {
  const urlObj = new URL(request.url);

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

export const onRequest = [requireAdminPassword, fetchFeed];
