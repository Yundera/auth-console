// Thin fetch wrapper. Every request goes through the AppShield gate with the
// session cookie; the custom header on writes is what the server's CSRF guard
// checks (a cross-site page cannot set it without a preflight we never answer).

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: unknown,
  ) {
    super(message)
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') {
    headers['X-Auth-Console'] = '1'
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  let data: unknown = undefined
  try {
    data = text ? JSON.parse(text) : undefined
  } catch {
    // The gate answers an expired session with a login page, not JSON.
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | undefined)?.error ?? `${res.status} ${res.statusText}`
    throw new ApiError(res.status, msg, data)
  }
  if (data === undefined) {
    throw new ApiError(res.status, 'Unexpected response — your session may have expired. Reload the page.')
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  del: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body),
}

export function errorText(e: unknown): string {
  if (e instanceof ApiError && e.status === 409 && /host action/.test(e.message)) {
    return 'Another host action is still running — try again in a moment.'
  }
  return e instanceof Error ? e.message : String(e)
}

// ---- response shapes (mirror internal/server/handlers.go) ----------------

export interface Me {
  identity: { user: string; email?: string; name?: string; groups?: string[]; method: string }
  isAdmin: boolean
  localAuthUrl: string
  logoutUrl: string
  version: string
}

export interface Capabilities {
  onboarding: boolean
  support: boolean
  dashboardAccount: string
}

export interface LocalUser {
  username: string
  displayname: string
  email: string
  groups: string[]
  disabled: boolean
  protected: boolean
}

export interface UsersResponse {
  users: LocalUser[]
  currentUser: string
  collectedAt: string
}

export interface Credentials {
  username: string
  password: string
}

export interface Onboarding {
  claimed: boolean
  completed: boolean
  username: string
}

export interface AuthorizedKey {
  type: string
  fingerprint: string
  bits: number | null
  comment: string
  isAdminKey: boolean
  isSupportKey: boolean
  isUserKey: boolean
}

export interface HostAccount {
  username: string
  uid: number
  gid: number
  home: string
  shell: string
  isSystem: boolean
  lastLoginTime: string | null
  lastLoginFrom: string | null
  authorizedKeys: AuthorizedKey[]
  authorizedKeysError: string | null
}

export interface LoginEvent {
  username: string
  terminal: string
  from: string
  time: string
  duration: string
}

export interface AccessInfo {
  accounts: HostAccount[]
  recentLogins: LoginEvent[]
  dashboardAccount: string
  collectedAt: string
}

export interface FetchedKey {
  url: string
  hostname: string
  trusted: boolean
  type: string
  publicKey: string
  comment: string
  fingerprint: string
}

export interface SupportStatus {
  ensure: boolean
  rawValue: string
  accessEnabled: boolean
  username: string
  fingerprint: string
  comment: string
}
