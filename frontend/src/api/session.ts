import type { User } from '../types';

export interface SessionState {
  accessToken: string;
  user: User;
}

export interface SessionChannel {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  close?(): void;
}

export interface LockRunner {
  run<T>(callback: () => Promise<T>): Promise<T>;
}

interface SessionMessage {
  type: 'session-updated' | 'session-cleared';
  source: string;
  sentAt: number;
  session?: SessionState;
}

const channelName = 'go-db-auth-session';
const refreshLockName = 'go-db-auth-refresh';
const peerSessionMaxAgeMs = 5_000;
const peerSessionWaitMs = 75;

export class AccessSessionStore {
  private accessToken: string | null = null;
  private user: User | null = null;

  getAccessToken(): string | null {
    return this.accessToken;
  }

  getUser(): User | null {
    return this.user;
  }

  getSnapshot(): SessionState | null {
    if (!this.accessToken || !this.user) {
      return null;
    }
    return { accessToken: this.accessToken, user: this.user };
  }

  set(session: SessionState): void {
    this.accessToken = session.accessToken;
    this.user = session.user;
  }

  clear(): void {
    this.accessToken = null;
    this.user = null;
  }
}

/**
 * Coordinates short-lived access sessions inside and across browser tabs.
 *
 * The access token remains in JavaScript memory. A BroadcastChannel carries a
 * new token only to same-origin tabs, while Web Locks serialize the refresh
 * operation so two tabs do not rotate the same refresh cookie concurrently.
 */
export class SessionCoordinator {
  private readonly store: AccessSessionStore;
  private readonly channel: SessionChannel | null;
  private readonly lockRunner: LockRunner | null;
  private readonly sourceId = createSourceId();
  private readonly channelListener: (event: MessageEvent) => void;
  private peerSession: SessionState | null = null;
  private peerSessionAt = 0;
  private refreshPromise: Promise<SessionState> | null = null;

  constructor(
    store = new AccessSessionStore(),
    channel: SessionChannel | null = null,
    lockRunner: LockRunner | null = null,
  ) {
    this.store = store;
    this.channel = channel;
    this.lockRunner = lockRunner;
    this.channelListener = (event) => this.handleChannelMessage(event);
    this.channel?.addEventListener('message', this.channelListener);
  }

  getAccessToken(): string | null {
    return this.store.getAccessToken();
  }

  getUser(): User | null {
    return this.store.getUser();
  }

  getSnapshot(): SessionState | null {
    return this.store.getSnapshot();
  }

  setSession(session: SessionState, broadcast = true): void {
    this.store.set(session);
    if (broadcast) {
      this.publish({ type: 'session-updated', session });
    }
  }

  clearSession(broadcast = true): void {
    this.store.clear();
    this.peerSession = null;
    this.peerSessionAt = 0;
    if (broadcast) {
      this.publish({ type: 'session-cleared' });
    }
  }

  /** Restore an in-memory session using the HttpOnly refresh cookie. */
  restore(performRefresh: () => Promise<SessionState>): Promise<SessionState> {
    const current = this.store.getSnapshot();
    if (current) {
      return Promise.resolve(current);
    }
    return this.runRefresh(performRefresh, true);
  }

  /** Refresh after an access-token rejection, reusing a newer peer session. */
  refresh(performRefresh: () => Promise<SessionState>): Promise<SessionState> {
    return this.runRefresh(performRefresh, false);
  }

  close(): void {
    this.channel?.removeEventListener('message', this.channelListener);
    this.channel?.close?.();
  }

  private runRefresh(
    performRefresh: () => Promise<SessionState>,
    requireMissingSession: boolean,
  ): Promise<SessionState> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    const startingAccessToken = this.store.getAccessToken();
    const operation = this.lockRunner
      ? this.lockRunner.run(async () => {
          await this.waitForPeerSession();
          const current = this.store.getSnapshot();
          const peer = this.freshPeerSession();
          if (peer && peer.accessToken !== startingAccessToken) {
            this.store.set(peer);
            return peer;
          }
          if (requireMissingSession && current) {
            return current;
          }
          return this.performAndPublish(performRefresh);
        })
      : this.performAndPublish(performRefresh);

    this.refreshPromise = operation.finally(() => {
      this.refreshPromise = null;
    });
    return this.refreshPromise;
  }

  private async performAndPublish(
    performRefresh: () => Promise<SessionState>,
  ): Promise<SessionState> {
    const session = await performRefresh();
    this.setSession(session);
    return session;
  }

  private publish(
    payload: Pick<SessionMessage, 'type' | 'session'>,
  ): void {
    if (!this.channel) {
      return;
    }
    const message: SessionMessage = {
      type: payload.type,
      source: this.sourceId,
      sentAt: Date.now(),
      ...(payload.session ? { session: payload.session } : {}),
    };
    this.channel.postMessage(message);
  }

  private handleChannelMessage(event: MessageEvent): void {
    const message = event.data as Partial<SessionMessage> | null;
    if (!message || message.source === this.sourceId || !message.type) {
      return;
    }
    if (message.type === 'session-cleared') {
      this.store.clear();
      this.peerSession = null;
      this.peerSessionAt = 0;
      return;
    }
    if (message.type !== 'session-updated' || !message.session?.accessToken) {
      return;
    }

    this.peerSession = message.session;
    this.peerSessionAt = Date.now();
    this.store.set(message.session);
  }

  private freshPeerSession(): SessionState | null {
    if (!this.peerSession || Date.now() - this.peerSessionAt > peerSessionMaxAgeMs) {
      return null;
    }
    return this.peerSession;
  }

  private async waitForPeerSession(): Promise<void> {
    if (!this.channel || this.freshPeerSession()) {
      return;
    }
    await new Promise<void>((resolve) => {
      globalThis.setTimeout(resolve, peerSessionWaitMs);
    });
  }
}

export function createBrowserSessionCoordinator(): SessionCoordinator {
  const channel = createBrowserChannel();
  const lockRunner = createBrowserLockRunner();
  return new SessionCoordinator(new AccessSessionStore(), channel, lockRunner);
}

function createBrowserChannel(): SessionChannel | null {
  if (typeof window === 'undefined' || typeof window.BroadcastChannel === 'undefined') {
    return null;
  }
  return new window.BroadcastChannel(channelName);
}

function createBrowserLockRunner(): LockRunner | null {
  if (typeof window === 'undefined' || !window.navigator?.locks) {
    return null;
  }
  return {
    run: async <T>(callback: () => Promise<T>): Promise<T> =>
      await window.navigator.locks.request(refreshLockName, async () => callback()),
  };
}

function createSourceId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}
