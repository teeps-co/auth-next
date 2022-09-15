import { IncomingMessage } from 'http';
import { AuthorizationParameters as OidcAuthorizationParameters } from 'openid-client';
import { LoginOptions, DeepPartial, getConfig as getBaseConfig } from './teeps-auth-session';

/**
 * @category server
 */
export interface BaseConfig {
  /**
   * The secret(s) used to derive an encryption key for the user identity in a session cookie and
   * to sign the transient cookies used by the login callback.
   * Use a single string key or array of keys for an encrypted session cookie.
   * You can also use the TEEPS_AUTH_SECRET environment variable.
   */
  secret: string | Array<string>;

  /**
   * Object defining application session cookie attributes.
   */
  session: SessionConfig;

  /**
   * Boolean value to enable TeepsAuth's proprietary logout feature.
   * Since this SDK is for TeepsAuth, it's set to `true`by default.
   */
  teepsAuthLogout: boolean;

  /**
   *  URL parameters used when redirecting users to the authorization server to log in.
   *
   *  If this property is not provided by your application, its default values will be:
   *
   * ```js
   * {
   *   response_type: 'code',
   *   scope: 'openid profile email'
   * }
   * ```
   *
   * New values can be passed in to change what is returned from the authorization server
   * depending on your specific scenario. Additional custom parameters can be added as well.
   *
   * **Note:** You must provide the required parameters if this object is set.
   *
   * ```js
   * {
   *   response_type: 'code',
   *   scope: 'openid profile email',
   *
   *   // Additional parameters
   *   acr_value: "tenant:test-tenant",
   *   custom_param: "custom-value"
   * };
   * ```
   */
  authorizationParams: AuthorizationParameters;

  /**
   * The root URL for the application router, eg https://localhost
   * You can also use the TEEPS_AUTH_BASE_URL environment variable.
   * If you provide a domain, we will prefix it with `https://` - This can be useful when assigning it to
   * `VERCEL_URL` for Vercel deploys
   */
  baseURL: string;

  /**
   * The Client ID for your application.
   * You can also use the TEEPS_AUTH_CLIENT_ID environment variable.
   */
  clientID: string;

  /**
   * The Client Secret for your application.
   * Required when requesting access tokens.
   * You can also use the TEEPS_AUTH_CLIENT_SECRET environment variable.
   */
  clientSecret?: string;

  /**
   * Integer value for the system clock's tolerance (leeway) in seconds for ID token verification.`
   * Default is 60
   * You can also use the TEEPS_AUTH_CLOCK_TOLERANCE environment variable.
   */
  clockTolerance: number;

  /**
   * Integer value for the http timeout in ms for authentication requests.
   * Default is 5000
   * You can also use the TEEPS_AUTH_HTTP_TIMEOUT environment variable.
   */
  httpTimeout: number;

  /**
   * To opt-out of sending the library and node version to your authorization server
   * via the `TeepsAuth-Client` header. Default is `true
   * You can also use the TEEPS_AUTH_ENABLE_TELEMETRY environment variable.
   */
  enableTelemetry: boolean;

  /**
   * Function that returns an object with URL-safe state values for login.
   * Used for passing custom state parameters to your authorization server.
   * Can also be passed in to {@link HandleLogin}
   *
   * ```js
   * {
   *   ...
   *   getLoginState(req, options) {
   *     return {
   *       returnTo: options.returnTo || req.originalUrl,
   *       customState: 'foo'
   *     };
   *   }
   * }
   * ``
   */
  getLoginState: (req: IncomingMessage, options: LoginOptions) => Record<string, any>;

  /**
   * Array value of claims to remove from the ID token before storing the cookie session.
   * Default is `['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash' ]`
   * You can also use the TEEPS_AUTH_IDENTITY_CLAIM_FILTER environment variable.
   */
  identityClaimFilter: string[];

  /**
   * Boolean value to log the user out from the identity provider on application logout. Default is `true`
   * You can also use the TEEPS_AUTH_IDP_LOGOUT environment variable.
   */
  idpLogout: boolean;

  /**
   * String value for the expected ID token algorithm. Default is 'RS256'
   * You can also use the TEEPS_AUTH_ID_TOKEN_SIGNING_ALG environment variable.
   */
  idTokenSigningAlg: string;

  /**
   * REQUIRED. The root URL for the token issuer with no trailing slash.
   * This is `https://` plus your TeepsAuth domain
   * You can also use the TEEPS_AUTH_ISSUER_BASE_URL environment variable.
   */
  issuerBaseURL: string;

  /**
   * Set a fallback cookie with no `SameSite` attribute when `response_mode` is `form_post`.
   * The default `response_mode` for this SDK is `query` so this defaults to `false`
   * You can also use the TEEPS_AUTH_LEGACY_SAME_SITE_COOKIE environment variable.
   */
  legacySameSiteCookie: boolean;

  /**
   * Boolean value to automatically install the login and logout routes.
   */
  routes: {
    /**
     * Either a relative path to the application or a valid URI to an external domain.
     * This value must be registered on the authorization server.
     * The user will be redirected to this after a logout has been performed.
     * You can also use the TEEPS_AUTH_POST_LOGOUT_REDIRECT environment variable.
     */
    postLogoutRedirect: string;

    /**
     * Relative path to the application callback to process the response from the authorization server.
     * Defaults to `/api/auth/callback`
     * You can also use the TEEPS_AUTH_CALLBACK environment variable.
     */
    callback: string;
  };
}

/**
 * Configuration parameters used for the application session.
 *
 * @category Server
 */
export interface SessionConfig {
  /**
   * String value for the cookie name used for the internal session.
   * This value must only include letters, numbers, and underscores.
   * Default is `appSession`.
   * You can also use the TEEPS_AUTH_SESSION_NAME environment variable.
   */
  name: string;

  /**
   * If you want your session duration to be rolling, eg reset everytime the
   * user is active on your site, set this to a `true`. If you want the session
   * duration to be absolute, where the user is logged out a fixed time after login,
   * regardless of activity, set this to `false`
   * Default is `true`.
   * You can also use the TEEPS_AUTH_SESSION_ROLLING environment variable.
   */
  rolling: boolean;

  /**
   * Integer value, in seconds, for application session rolling duration.
   * The amount of time for which the user must be idle for then to be logged out.
   * Should be false when rolling is false.
   * Default is 86400 seconds (1 day).
   * You can also use the TEEPS_AUTH_SESSION_ROLLING_DURATION environment variable.
   */
  rollingDuration: number | false;

  /**
   * Integer value, in seconds, for application absolute rolling duration.
   * The amount of time after the user has logged in that they will be logged out.
   * Set this to `false` if you don't want an absolute duration on your session.
   * Default is 604800 seconds (7 days).
   * You can also use the TEEPS_AUTH_SESSION_ABSOLUTE_DURATION environment variable.
   */
  absoluteDuration: boolean | number;

  cookie: CookieConfig;
}

/**
 * Configure how the session cookie and transient cookies are stored.
 *
 * @category Server
 */
export interface CookieConfig {
  /**
   * Domain name for the cookie.
   * You can also use the TEEPS_AUTH_COOKIE_DOMAIN environment variable.
   */
  domain?: string;

  /**
   * Path for the cookie.
   * This defaults to `/`
   * You should change this to be more restrictive if you application shares a domain with other apps.
   * You can also use the TEEPS_AUTH_COOKIE_PATH environment variable.
   */
  path?: string;

  /**
   * Set to true to use a transient cookie (cookie without an explicit expiration).
   * Default is `false`
   * You can also use the TEEPS_AUTH_COOKIE_TRANSIENT environment variable.
   */
  transient: boolean;

  /**
   * Flags the cookie to be accessible only by the web server.
   * Defaults to `true`.
   * You can also use the TEEPS_AUTH_COOKIE_HTTP_ONLY environment variable.
   */
  httpOnly: boolean;

  /**
   * Marks the cookie to be used over secure channels only.
   * Defaults to the protocol of {@link BaseConfig.baseURL}.
   * You can also use the TEEPS_AUTH_COOKIE_SECURE environment variable.
   */
  secure?: boolean;

  /**
   * Value of the SameSite Set-Cookie attribute.
   * Defaults to "lax" but will be adjusted based on {@link AuthorizationParameters.response_type}.
   * You can also use the TEEPS_AUTH_COOKIE_SAME_SITE environment variable.
   */
  sameSite: 'lax' | 'strict' | 'none';
}

/**
 * Authorization parameters that will be passed to the identity provider on login.
 *
 * The library uses `response_mode: 'query'` and `response_type: 'code'` (with PKCE) by default.
 *
 * @category Server
 */
export interface AuthorizationParameters extends OidcAuthorizationParameters {
  scope: string;
  response_mode: 'query' | 'form_post';
  response_type: 'id_token' | 'code id_token' | 'code';
}

/**
 * @category server
 */
export interface NextConfig extends Pick<BaseConfig, 'identityClaimFilter'> {
  /**
   * Log users in to a specific organization.
   *
   * This will specify an `organization` parameter in your user's login request and will add a step to validate
   * the `org_id` claim in your user's ID Token.
   *
   * If your app supports multiple organizations, you should take a look at {@Link AuthorizationParams.organization}
   */
  organization?: string;
  routes: {
    login: string;
  };
}

/**
 * ## Configuration properties.
 *
 * The Server part of the SDK can be configured in 2 ways.
 *
 * ### 1. Environmental Variables
 *
 * The simplest way to use the SDK is to use the named exports ({@link HandleAuth}, {@link HandleLogin},
 * {@link HandleLogout}, {@link HandleCallback}, {@link HandleProfile}, {@link GetSession}, {@link GetAccessToken},
 * {@link WithApiAuthRequired} and {@link WithPageAuthRequired}), eg:
 *
 * ```js
 * // pages/api/auth/[...teeps-auth].js
 * import { handleAuth } from '@teeps-co/teeps-auth-next';
 *
 * return handleAuth();
 * ```
 *
 * When you use these named exports, an instance of the SDK is created for you which you can configure using
 * environmental variables:
 *
 * ### Required
 *
 * - `TEEPS_AUTH_SECRET`: See {@link secret}
 * - `TEEPS_AUTH_ISSUER_BASE_URL`: See {@link issuerBaseURL}
 * - `TEEPS_AUTH_BASE_URL`: See {@link baseURL}
 * - `TEEPS_AUTH_CLIENT_ID`: See {@link clientID}
 * - `TEEPS_AUTH_CLIENT_SECRET`: See {@link clientSecret}
 *
 * ### Optional
 *
 * - `TEEPS_AUTH_CLOCK_TOLERANCE`: See {@link clockTolerance}
 * - `TEEPS_AUTH_HTTP_TIMEOUT`: See {@link httpTimeout}
 * - `TEEPS_AUTH_ENABLE_TELEMETRY`: See {@link enableTelemetry}
 * - `TEEPS_AUTH_IDP_LOGOUT`: See {@link idpLogout}
 * - `TEEPS_AUTH_ID_TOKEN_SIGNING_ALG`: See {@link idTokenSigningAlg}
 * - `TEEPS_AUTH_LEGACY_SAME_SITE_COOKIE`: See {@link legacySameSiteCookie}
 * - `TEEPS_AUTH_IDENTITY_CLAIM_FILTER`: See {@link identityClaimFilter}
 * - `NEXT_PUBLIC_TEEPS_AUTH_LOGIN`: See {@link NextConfig.routes}
 * - `TEEPS_AUTH_CALLBACK`: See {@link BaseConfig.routes}
 * - `TEEPS_AUTH_POST_LOGOUT_REDIRECT`: See {@link BaseConfig.routes}
 * - `TEEPS_AUTH_AUDIENCE`: See {@link BaseConfig.authorizationParams}
 * - `TEEPS_AUTH_SCOPE`: See {@link BaseConfig.authorizationParams}
 * - `TEEPS_AUTH_ORGANIZATION`: See {@link NextConfig.organization}
 * - `TEEPS_AUTH_SESSION_NAME`: See {@link SessionConfig.name}
 * - `TEEPS_AUTH_SESSION_ROLLING`: See {@link SessionConfig.rolling}
 * - `TEEPS_AUTH_SESSION_ROLLING_DURATION`: See {@link SessionConfig.rollingDuration}
 * - `TEEPS_AUTH_SESSION_ABSOLUTE_DURATION`: See {@link SessionConfig.absoluteDuration}
 * - `TEEPS_AUTH_COOKIE_DOMAIN`: See {@link CookieConfig.domain}
 * - `TEEPS_AUTH_COOKIE_PATH`: See {@link CookieConfig.path}
 * - `TEEPS_AUTH_COOKIE_TRANSIENT`: See {@link CookieConfig.transient}
 * - `TEEPS_AUTH_COOKIE_HTTP_ONLY`: See {@link CookieConfig.httpOnly}
 * - `TEEPS_AUTH_COOKIE_SECURE`: See {@link CookieConfig.secure}
 * - `TEEPS_AUTH_COOKIE_SAME_SITE`: See {@link CookieConfig.sameSite}
 *
 * ### 2. Create your own instance using {@link InitTeepsAuth}
 *
 * If you don't want to configure the SDK with environment variables or you want more fine grained control over the
 * instance, you can create an instance yourself and use the handlers and helpers from that.
 *
 * First, export your configured instance from another module:
 *
 * ```js
 * // utils/teepsAuth.js
 * import { initTeepsAuth } from '@teeps-co/teeps-auth-next';
 *
 * export default initTeepsAuth({ ...ConfigParameters... });
 * ```
 *
 * Then import it into your route handler:
 *
 * ```js
 * // pages/api/auth/[...teeps-auth].js
 * import teepsAuth from '../../../../utils/teeps-auth';
 *
 * return teepsAuth.handleAuth();
 * ```
 *
 * **Note** If you use {@link InitTeepsAuth}, you should *not* use the other named exports as they will use a different
 * instance of the SDK.
 *
 * @category Server
 */
export type ConfigParameters = DeepPartial<BaseConfig & NextConfig>;

/**
 * @ignore
 */
const FALSEY = ['n', 'no', 'false', '0', 'off'];

/**
 * @ignore
 */
const bool = (param?: any, defaultValue?: boolean): boolean | undefined => {
  if (param === undefined || param === '') return defaultValue;
  if (param && typeof param === 'string') return !FALSEY.includes(param.toLowerCase().trim());
  return !!param;
};

/**
 * @ignore
 */
const num = (param?: string): number | undefined => (param === undefined || param === '' ? undefined : +param);

/**
 * @ignore
 */
const array = (param?: string): string[] | undefined =>
  param === undefined || param === '' ? undefined : param.replace(/\s/g, '').split(',');

/**
 * @ignore
 */
export const getLoginUrl = (): string => {
  return process.env.NEXT_PUBLIC_TEEPS_AUTH_LOGIN || '/api/auth/login';
};

/**
 * @ignore
 */
export const getConfig = (params: ConfigParameters = {}): { baseConfig: BaseConfig; nextConfig: NextConfig } => {
  // Don't use destructuring here so that the `DefinePlugin` can replace any env vars specified in `next.config.js`
  const TEEPS_AUTH_SECRET = process.env.TEEPS_AUTH_SECRET;
  const TEEPS_AUTH_ISSUER_BASE_URL = process.env.TEEPS_AUTH_ISSUER_BASE_URL;
  const TEEPS_AUTH_BASE_URL = process.env.TEEPS_AUTH_BASE_URL;
  const TEEPS_AUTH_CLIENT_ID = process.env.TEEPS_AUTH_CLIENT_ID;
  const TEEPS_AUTH_CLIENT_SECRET = process.env.TEEPS_AUTH_CLIENT_SECRET;
  const TEEPS_AUTH_CLOCK_TOLERANCE = process.env.TEEPS_AUTH_CLOCK_TOLERANCE;
  const TEEPS_AUTH_HTTP_TIMEOUT = process.env.TEEPS_AUTH_HTTP_TIMEOUT;
  const TEEPS_AUTH_ENABLE_TELEMETRY = process.env.TEEPS_AUTH_ENABLE_TELEMETRY;
  const TEEPS_AUTH_IDP_LOGOUT = process.env.TEEPS_AUTH_IDP_LOGOUT;
  const TEEPS_AUTH_ID_TOKEN_SIGNING_ALG = process.env.TEEPS_AUTH_ID_TOKEN_SIGNING_ALG;
  const TEEPS_AUTH_LEGACY_SAME_SITE_COOKIE = process.env.TEEPS_AUTH_LEGACY_SAME_SITE_COOKIE;
  const TEEPS_AUTH_IDENTITY_CLAIM_FILTER = process.env.TEEPS_AUTH_IDENTITY_CLAIM_FILTER;
  const TEEPS_AUTH_CALLBACK = process.env.TEEPS_AUTH_CALLBACK;
  const TEEPS_AUTH_POST_LOGOUT_REDIRECT = process.env.TEEPS_AUTH_POST_LOGOUT_REDIRECT;
  const TEEPS_AUTH_AUDIENCE = process.env.TEEPS_AUTH_AUDIENCE;
  const TEEPS_AUTH_SCOPE = process.env.TEEPS_AUTH_SCOPE;
  const TEEPS_AUTH_ORGANIZATION = process.env.TEEPS_AUTH_ORGANIZATION;
  const TEEPS_AUTH_SESSION_NAME = process.env.TEEPS_AUTH_SESSION_NAME;
  const TEEPS_AUTH_SESSION_ROLLING = process.env.TEEPS_AUTH_SESSION_ROLLING;
  const TEEPS_AUTH_SESSION_ROLLING_DURATION = process.env.TEEPS_AUTH_SESSION_ROLLING_DURATION;
  const TEEPS_AUTH_SESSION_ABSOLUTE_DURATION = process.env.TEEPS_AUTH_SESSION_ABSOLUTE_DURATION;
  const TEEPS_AUTH_COOKIE_DOMAIN = process.env.TEEPS_AUTH_COOKIE_DOMAIN;
  const TEEPS_AUTH_COOKIE_PATH = process.env.TEEPS_AUTH_COOKIE_PATH;
  const TEEPS_AUTH_COOKIE_TRANSIENT = process.env.TEEPS_AUTH_COOKIE_TRANSIENT;
  const TEEPS_AUTH_COOKIE_HTTP_ONLY = process.env.TEEPS_AUTH_COOKIE_HTTP_ONLY;
  const TEEPS_AUTH_COOKIE_SECURE = process.env.TEEPS_AUTH_COOKIE_SECURE;
  const TEEPS_AUTH_COOKIE_SAME_SITE = process.env.TEEPS_AUTH_COOKIE_SAME_SITE;

  const baseURL =
    TEEPS_AUTH_BASE_URL && !/^https?:\/\//.test(TEEPS_AUTH_BASE_URL as string)
      ? `https://${TEEPS_AUTH_BASE_URL}`
      : TEEPS_AUTH_BASE_URL;

  const { organization, ...baseParams } = params;

  const baseConfig = getBaseConfig({
    secret: TEEPS_AUTH_SECRET,
    issuerBaseURL: TEEPS_AUTH_ISSUER_BASE_URL,
    baseURL: baseURL,
    clientID: TEEPS_AUTH_CLIENT_ID,
    clientSecret: TEEPS_AUTH_CLIENT_SECRET,
    clockTolerance: num(TEEPS_AUTH_CLOCK_TOLERANCE),
    httpTimeout: num(TEEPS_AUTH_HTTP_TIMEOUT),
    enableTelemetry: bool(TEEPS_AUTH_ENABLE_TELEMETRY),
    idpLogout: bool(TEEPS_AUTH_IDP_LOGOUT, true),
    teepsAuthLogout: bool(TEEPS_AUTH_IDP_LOGOUT, true),
    idTokenSigningAlg: TEEPS_AUTH_ID_TOKEN_SIGNING_ALG,
    legacySameSiteCookie: bool(TEEPS_AUTH_LEGACY_SAME_SITE_COOKIE),
    identityClaimFilter: array(TEEPS_AUTH_IDENTITY_CLAIM_FILTER),
    ...baseParams,
    authorizationParams: {
      response_type: 'code',
      audience: TEEPS_AUTH_AUDIENCE,
      scope: TEEPS_AUTH_SCOPE,
      ...baseParams.authorizationParams
    },
    session: {
      name: TEEPS_AUTH_SESSION_NAME,
      rolling: bool(TEEPS_AUTH_SESSION_ROLLING),
      rollingDuration:
        TEEPS_AUTH_SESSION_ROLLING_DURATION && isNaN(Number(TEEPS_AUTH_SESSION_ROLLING_DURATION))
          ? (bool(TEEPS_AUTH_SESSION_ROLLING_DURATION) as false)
          : num(TEEPS_AUTH_SESSION_ROLLING_DURATION),
      absoluteDuration:
        TEEPS_AUTH_SESSION_ABSOLUTE_DURATION && isNaN(Number(TEEPS_AUTH_SESSION_ABSOLUTE_DURATION))
          ? bool(TEEPS_AUTH_SESSION_ABSOLUTE_DURATION)
          : num(TEEPS_AUTH_SESSION_ABSOLUTE_DURATION),
      ...baseParams.session,
      cookie: {
        domain: TEEPS_AUTH_COOKIE_DOMAIN,
        path: TEEPS_AUTH_COOKIE_PATH || '/',
        transient: bool(TEEPS_AUTH_COOKIE_TRANSIENT),
        httpOnly: bool(TEEPS_AUTH_COOKIE_HTTP_ONLY),
        secure: bool(TEEPS_AUTH_COOKIE_SECURE),
        sameSite: TEEPS_AUTH_COOKIE_SAME_SITE as 'lax' | 'strict' | 'none' | undefined,
        ...baseParams.session?.cookie
      }
    },
    routes: {
      callback: baseParams.routes?.callback || TEEPS_AUTH_CALLBACK || '/api/auth/callback',
      postLogoutRedirect: baseParams.routes?.postLogoutRedirect || TEEPS_AUTH_POST_LOGOUT_REDIRECT
    }
  });

  const nextConfig = {
    routes: {
      ...baseConfig.routes,
      login: baseParams.routes?.login || getLoginUrl()
    },
    identityClaimFilter: baseConfig.identityClaimFilter,
    organization: organization || TEEPS_AUTH_ORGANIZATION
  };

  return { baseConfig, nextConfig };
};
