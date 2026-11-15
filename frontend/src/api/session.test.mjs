import test from 'node:test';
import assert from 'node:assert/strict';
import { SessionCoordinator } from './session.ts';

class FakeChannel {
  constructor(hub) {
    this.hub = hub;
    this.listeners = new Set();
    hub.channels.add(this);
  }

  postMessage(message) {
    queueMicrotask(() => {
      for (const peer of this.hub.channels) {
        if (peer === this) continue;
        for (const listener of peer.listeners) {
          listener({ data: structuredClone(message) });
        }
      }
    });
  }

  addEventListener(type, listener) {
    if (type === 'message') this.listeners.add(listener);
  }

  removeEventListener(type, listener) {
    if (type === 'message') this.listeners.delete(listener);
  }

  close() {
    this.hub.channels.delete(this);
  }
}

class ChannelHub {
  constructor() {
    this.channels = new Set();
  }
}

class SerialLockRunner {
  constructor() {
    this.tail = Promise.resolve();
  }

  run(callback) {
    const result = this.tail.then(callback);
    this.tail = result.then(() => undefined, () => undefined);
    return result;
  }
}

function user() {
  return {
    id: 'user-1',
    name: 'Owner',
    email: 'owner@example.com',
    role: 'user',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  };
}

test('two tabs share one refresh and receive the same in-memory session', async () => {
  const hub = new ChannelHub();
  const locks = new SerialLockRunner();
  const first = new SessionCoordinator(undefined, new FakeChannel(hub), locks);
  const second = new SessionCoordinator(undefined, new FakeChannel(hub), locks);
  let refreshCalls = 0;

  const performRefresh = async () => {
    refreshCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return { accessToken: 'shared-access', user: user() };
  };

  const sessions = await Promise.all([
    first.restore(performRefresh),
    second.restore(performRefresh),
  ]);

  assert.equal(refreshCalls, 1);
  assert.equal(sessions[0].accessToken, 'shared-access');
  assert.equal(sessions[1].accessToken, 'shared-access');
  assert.equal(first.getAccessToken(), 'shared-access');
  assert.equal(second.getAccessToken(), 'shared-access');

  first.clearSession();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(first.getAccessToken(), null);
  assert.equal(second.getAccessToken(), null);

  first.close();
  second.close();
});
