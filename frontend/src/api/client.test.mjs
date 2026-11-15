import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import {
  api,
  authAPI,
  authClient,
  clearAccessSession,
  isAuthenticationFailure,
  restoreSession,
  sessionCoordinator,
  setAccessSession,
} from './client.ts';

function installBrowserGlobals() {
  globalThis.localStorage = {
    getItem() {
      throw new Error('access tokens must not be read from localStorage');
    },
    setItem() {
      throw new Error('access tokens must not be written to localStorage');
    },
    removeItem() {
      throw new Error('access tokens must not be removed from localStorage');
    },
  };
  globalThis.window = {
    location: {
      pathname: '/dashboard',
      href: '',
    },
  };
}

function session(accessToken = 'old-access') {
  return {
    access_token: accessToken,
    user: {
      id: 'user-1',
      name: 'Owner',
      email: 'owner@example.com',
      role: 'user',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    },
  };
}

function success(config, data, status = 200) {
  return {
    data,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: {},
    config,
    request: {},
  };
}

function httpError(config, status, message) {
  return new axios.AxiosError(message, `HTTP_${status}`, config, null, {
    status,
    statusText: message,
    headers: {},
    config,
  });
}

beforeEach(() => {
  installBrowserGlobals();
  clearAccessSession(false);
  api.defaults.adapter = undefined;
  authClient.defaults.adapter = undefined;
});

test('a protected 401 refreshes once and retries with the new in-memory access token', async () => {
  setAccessSession(session());

  let protectedCalls = 0;
  let refreshCalls = 0;
  api.defaults.adapter = async (config) => {
    protectedCalls += 1;
    if (protectedCalls === 1) {
      throw httpError(config, 401, 'expired access token');
    }
    assert.equal(config.headers.Authorization, 'Bearer new-access');
    return success(config, { success: true, data: { id: 'user-1' } });
  };
  authClient.defaults.adapter = async (config) => {
    refreshCalls += 1;
    return success(config, {
      success: true,
      data: session('new-access'),
    });
  };

  const response = await api.get('/users/me');
  assert.equal(protectedCalls, 2);
  assert.equal(refreshCalls, 1);
  assert.equal(response.data.data.id, 'user-1');
  assert.equal(sessionCoordinator.getAccessToken(), 'new-access');
});

test('initial load and reload restore the session through the HttpOnly cookie', async () => {
  let refreshCalls = 0;
  authClient.defaults.adapter = async (config) => {
    refreshCalls += 1;
    assert.match(config.url, /\/auth\/refresh$/);
    return success(config, {
      success: true,
      data: session(`restored-access-${refreshCalls}`),
    });
  };

  const restored = await restoreSession();
  assert.equal(restored?.accessToken, 'restored-access-1');
  assert.equal(sessionCoordinator.getAccessToken(), 'restored-access-1');

  clearAccessSession(false);
  const restoredAfterReload = await restoreSession();
  assert.equal(restoredAfterReload?.accessToken, 'restored-access-2');
  assert.equal(refreshCalls, 2);
});

test('concurrent protected requests share one refresh operation', async () => {
  setAccessSession(session());

  let protectedCalls = 0;
  let refreshCalls = 0;
  api.defaults.adapter = async (config) => {
    protectedCalls += 1;
    if (protectedCalls <= 2) {
      throw httpError(config, 401, 'expired access token');
    }
    assert.equal(config.headers.Authorization, 'Bearer shared-access');
    return success(config, { success: true, data: { id: 'user-1' } });
  };
  authClient.defaults.adapter = async (config) => {
    refreshCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 10));
    return success(config, {
      success: true,
      data: session('shared-access'),
    });
  };

  const responses = await Promise.all([
    api.get('/users/me'),
    api.get('/tasks'),
  ]);
  assert.equal(protectedCalls, 4);
  assert.equal(refreshCalls, 1);
  assert.equal(responses[0].data.data.id, 'user-1');
  assert.equal(responses[1].data.data.id, 'user-1');
});

test('a transient refresh failure preserves the existing in-memory access token', async () => {
  setAccessSession(session());

  let protectedCalls = 0;
  api.defaults.adapter = async (config) => {
    protectedCalls += 1;
    throw httpError(config, 401, 'expired access token');
  };
  authClient.defaults.adapter = async (config) => {
    throw httpError(config, 503, 'session store unavailable');
  };

  await assert.rejects(api.get('/users/me'));
  assert.equal(protectedCalls, 1);
  assert.equal(sessionCoordinator.getAccessToken(), 'old-access');
});

test('a refresh 401 clears the in-memory access session', async () => {
  setAccessSession(session());

  api.defaults.adapter = async (config) => {
    throw httpError(config, 401, 'expired access token');
  };
  authClient.defaults.adapter = async (config) => {
    throw httpError(config, 401, 'invalid refresh session');
  };

  await assert.rejects(api.get('/users/me'));
  assert.equal(sessionCoordinator.getAccessToken(), null);
  assert.equal(globalThis.window.location.href, '/login');
});

test('a retried request is not refreshed more than once', async () => {
  setAccessSession(session());

  let protectedCalls = 0;
  let refreshCalls = 0;
  api.defaults.adapter = async (config) => {
    protectedCalls += 1;
    throw httpError(config, 401, 'invalid access token');
  };
  authClient.defaults.adapter = async (config) => {
    refreshCalls += 1;
    return success(config, {
      success: true,
      data: session('rotated-access'),
    });
  };

  await assert.rejects(api.get('/users/me'));
  assert.equal(protectedCalls, 2);
  assert.equal(refreshCalls, 1);
  assert.equal(sessionCoordinator.getAccessToken(), null);
});

test('logout revokes the cookie session and clears local memory', async () => {
  setAccessSession(session());

  let logoutCalls = 0;
  authClient.defaults.adapter = async (config) => {
    logoutCalls += 1;
    assert.match(config.url, /\/auth\/logout$/);
    return success(config, undefined, 204);
  };

  await authAPI.logout();
  assert.equal(logoutCalls, 1);
  assert.equal(sessionCoordinator.getAccessToken(), null);
  assert.equal(globalThis.window.location.href, '/login');
});

test('a failed login does not attempt refresh or clear an existing session', async () => {
  setAccessSession(session('existing-access'));

  let authCalls = 0;
  authClient.defaults.adapter = async (config) => {
    authCalls += 1;
    assert.match(config.url, /\/auth\/login$/);
    throw httpError(config, 401, 'invalid credentials');
  };

  await assert.rejects(authAPI.login('owner@example.com', 'wrong-password'));
  assert.equal(authCalls, 1);
  assert.equal(sessionCoordinator.getAccessToken(), 'existing-access');
});

test('authentication failure classification ignores a transient refresh failure', () => {
  const transient = httpError({ _refreshTransientFailure: true }, 401, 'expired access token');
  const terminal = httpError({}, 401, 'invalid session');
  assert.equal(isAuthenticationFailure(transient), false);
  assert.equal(isAuthenticationFailure(terminal), true);
});
