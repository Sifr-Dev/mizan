import test from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { api, authAPI, authClient, isAuthenticationFailure } from './client.ts';

function installBrowserGlobals() {
  const values = new Map();
  globalThis.localStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    clear: () => values.clear(),
    key: (index) => [...values.keys()][index] ?? null,
    get length() {
      return values.size;
    },
  };
  globalThis.window = {
    location: {
      pathname: '/dashboard',
      href: '',
    },
  };
  return values;
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

test('a protected 401 refreshes once and retries with the new access token', async () => {
  const storage = installBrowserGlobals();
  storage.set('access_token', 'old-access');

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
      data: {
        access_token: 'new-access',
        user: { id: 'user-1', name: 'Owner', email: 'owner@example.com' },
      },
    });
  };

  const response = await api.get('/users/me');
  assert.equal(protectedCalls, 2);
  assert.equal(refreshCalls, 1);
  assert.equal(response.data.data.id, 'user-1');
  assert.equal(storage.get('access_token'), 'new-access');
});

test('a transient refresh failure preserves the existing access token', async () => {
  const storage = installBrowserGlobals();
  storage.set('access_token', 'old-access');

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
  assert.equal(storage.get('access_token'), 'old-access');
});

test('a refresh 401 clears the local access session', async () => {
  const storage = installBrowserGlobals();
  storage.set('access_token', 'old-access');

  api.defaults.adapter = async (config) => {
    throw httpError(config, 401, 'expired access token');
  };
  authClient.defaults.adapter = async (config) => {
    throw httpError(config, 401, 'invalid refresh session');
  };

  await assert.rejects(api.get('/users/me'));
  assert.equal(storage.get('access_token'), undefined);
  assert.equal(globalThis.window.location.href, '/login');
});

test('a failed login does not attempt refresh or clear an existing session', async () => {
  const storage = installBrowserGlobals();
  storage.set('access_token', 'existing-access');

  let authCalls = 0;
  authClient.defaults.adapter = async (config) => {
    authCalls += 1;
    assert.match(config.url, /\/auth\/login$/);
    throw httpError(config, 401, 'invalid credentials');
  };

  await assert.rejects(authAPI.login('owner@example.com', 'wrong-password'));
  assert.equal(authCalls, 1);
  assert.equal(storage.get('access_token'), 'existing-access');
});

test('authentication failure classification ignores a transient refresh failure', () => {
  const transient = httpError({ _refreshTransientFailure: true }, 401, 'expired access token');
  const terminal = httpError({}, 401, 'invalid session');
  assert.equal(isAuthenticationFailure(transient), false);
  assert.equal(isAuthenticationFailure(terminal), true);
});
