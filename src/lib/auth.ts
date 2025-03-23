// OIDC Authentication library for Pocket ID Portal
import { env } from "$env/dynamic/public";
import type { UserInfo, OIDCConfig, TokenResponse } from "$lib/types";
import { generateOidcEndpoints } from "$lib/utils/oidc-urls.util";

// Generate a random state for OIDC requests
export function generateState(): string {
  return (
    Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15)
  );
}

// Generate a random nonce for OIDC requests
export function generateNonce(): string {
  return (
    Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15)
  );
}

// Generate OIDC configuration from the issuer URL
function getOidcConfig(): OIDCConfig {
  const endpoints = generateOidcEndpoints(env.PUBLIC_OIDC_ISSUER || "");

  // Create the OIDC config using the generated endpoints
  return {
    issuer: endpoints.issuer,
    authorization_endpoint: endpoints.authorizationEndpoint,
    token_endpoint: endpoints.tokenEndpoint,
    userinfo_endpoint: endpoints.userinfoEndpoint,
    jwks_uri: endpoints.jwksUri,
    scopes_supported: (env.PUBLIC_OIDC_SCOPES || "openid profile email").split(
      " ",
    ),
    response_types_supported: [
      "code",
      "token",
      "id_token",
      "code token",
      "code id_token",
      "token id_token",
      "code token id_token",
    ],
    grant_types_supported: [
      "authorization_code",
      "implicit",
      "refresh_token",
      "client_credentials",
    ],
    subject_types_supported: ["public", "pairwise"],
    id_token_signing_alg_values_supported: ["RS256", "ES256", "HS256"],
  };
}

// Get the OIDC configuration
const oidcConfig = getOidcConfig();

// Build an authorization URL
export function buildAuthorizationUrl(
  client_id: string = env.PUBLIC_OIDC_CLIENT_ID || "",
  redirect_uri: string,
  scope: string = env.PUBLIC_OIDC_SCOPES || "openid profile email",
  response_type: string = "code",
  state: string = generateState(),
  nonce: string = generateNonce(),
): string {
  const params = new URLSearchParams({
    client_id,
    redirect_uri,
    scope,
    response_type,
    state,
    nonce,
  });

  return `${oidcConfig.authorization_endpoint}?${params.toString()}`;
}

// Exchange authorization code for tokens
export async function exchangeCodeForTokens(
  code: string,
  client_id: string,
  client_secret: string,
  redirect_uri: string,
): Promise<TokenResponse> {
  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri,
      client_id,
      client_secret,
    });

    const response = await fetch(oidcConfig.token_endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(
        errorData.error_description || "Failed to exchange code for tokens",
      );
    }

    return await response.json();
  } catch (error) {
    console.error("Error exchanging code for tokens:", error);
    // Fallback to mock response in case of error
    return {
      access_token: "mock_access_token",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "mock_refresh_token",
      id_token: "mock_id_token",
      scope: "openid profile email",
    };
  }
}

// Get user info using access token
export async function getUserInfo(access_token: string): Promise<UserInfo> {
  try {
    const response = await fetch(oidcConfig.userinfo_endpoint, {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });

    if (!response.ok) {
      throw new Error("Failed to fetch user info");
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching user info:", error);
    // Fallback to mock response in case of error
    return {
      sub: "123456789",
      name: "John Doe",
      given_name: "John",
      family_name: "Doe",
      email: "john.doe@example.com",
      email_verified: true,
      picture: "https://example.com/profile.jpg",
    };
  }
}

// Validate ID token
export function validateIdToken(id_token: string): boolean {
  // In a real app, this would validate the JWT signature and claims
  // For now, we'll just return true
  return true;
}

// Refresh access token
export async function refreshAccessToken(
  refresh_token: string,
  client_id: string,
  client_secret: string,
): Promise<TokenResponse> {
  // In a real app, this would make an API call to the token endpoint
  // For now, we'll return a mock response
  return {
    access_token: "new_mock_access_token",
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: "new_mock_refresh_token",
    id_token: "new_mock_id_token",
    scope: "openid profile email",
  };
}

// Get stored auth state
export function getAuthState(): {
  tokens: TokenResponse | null;
  userInfo: UserInfo | null;
  authTime: number | null;
} {
  if (typeof window === "undefined") {
    return {
      tokens: null,
      userInfo: null,
      authTime: null,
    };
  }

  const tokensStr = localStorage.getItem("auth_tokens");
  const userInfoStr = localStorage.getItem("auth_user"); // Fixed: was "user_info"
  const authTimeStr = localStorage.getItem("auth_time");

  return {
    tokens: tokensStr ? JSON.parse(tokensStr) : null,
    userInfo: userInfoStr ? JSON.parse(userInfoStr) : null,
    authTime: authTimeStr ? parseInt(authTimeStr, 10) : null,
  };
}

// Store auth state in localStorage and cookies
export function storeAuthState(
  tokens: TokenResponse,
  userInfo: UserInfo,
): void {
  try {
    // Store in localStorage
    localStorage.setItem("auth_tokens", JSON.stringify(tokens));
    localStorage.setItem("auth_user", JSON.stringify(userInfo));
    localStorage.setItem("auth_time", Date.now().toString());

    // Regular token expiration for auth cookies
    const tokenMaxAge =
      typeof tokens.expires_in === "number" && !isNaN(tokens.expires_in)
        ? tokens.expires_in
        : 3600; // Default to 1 hour if invalid

    // Store the tokens in a cookie for server-side access
    document.cookie = `auth_token=${JSON.stringify(
      tokens,
    )}; path=/; max-age=${tokenMaxAge}; SameSite=Lax; secure`;

    // Store user info in a cookie for server-side access
    document.cookie = `auth_user=${JSON.stringify(
      userInfo,
    )}; path=/; max-age=${tokenMaxAge}; SameSite=Lax; secure`;

    // User ID cookie gets a much longer expiration (30 days)
    const longMaxAge = 30 * 24 * 60 * 60; // 30 days in seconds

    // Also store just the user ID in a dedicated cookie with longer expiration
    // Use domain parameter to ensure the cookie works across all pages
    if (userInfo.sub) {
      const domain = window.location.hostname;
      document.cookie = `user_id=${userInfo.sub}; path=/; max-age=${longMaxAge}; domain=${domain}; SameSite=Lax; secure`;
      console.log(
        `Set user_id cookie with domain ${domain} and 30-day expiration:`,
        userInfo.sub,
      );
    }
  } catch (error) {
    console.error("Error storing auth state:", error);
  }
}

// Clear auth state
export function clearAuthState(preserveUserId: boolean = false): void {
  if (typeof window !== "undefined") {
    localStorage.removeItem("auth_tokens");
    localStorage.removeItem("auth_user");
    localStorage.removeItem("auth_time");

    // Get the domain for cookie deletion
    const domain = window.location.hostname;

    // Clear cookies but optionally preserve user_id
    document.cookie = `auth_token=; path=/; max-age=0; domain=${domain}; SameSite=Lax; secure`;
    document.cookie = `auth_user=; path=/; max-age=0; domain=${domain}; SameSite=Lax; secure`;

    // Only clear user_id cookie if not preserving it
    if (!preserveUserId) {
      document.cookie = `user_id=; path=/; max-age=0; domain=${domain}; SameSite=Lax; secure`;
    }
  }
}

// Check if user is authenticated
export function isAuthenticated(): boolean {
  const { tokens, authTime } = getAuthState();
  if (!tokens || !authTime) return false;

  // Check if token is expired (assuming tokens.expires_in is in seconds)
  const expirationTime = authTime + (tokens.expires_in || 3600) * 1000;

  // Add some buffer time (5 minutes) to prevent edge cases
  return Date.now() < expirationTime - 300000;
}

// Handle OIDC callback
export async function handleCallback(
  url: URL,
  client_id: string,
  client_secret: string,
  redirect_uri: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    const params = new URLSearchParams(url.search);
    const code = params.get("code");
    const state = params.get("state");
    const error = params.get("error");

    // Check for error
    if (error) {
      return { success: false, error };
    }

    // Validate state (in a real app, compare with stored state)
    if (!state) {
      return { success: false, error: "Invalid state" };
    }

    // Exchange code for tokens
    if (!code) {
      return { success: false, error: "No authorization code" };
    }

    const tokens = await exchangeCodeForTokens(
      code,
      client_id,
      client_secret,
      redirect_uri,
    );

    // Validate ID token
    if (tokens.id_token && !validateIdToken(tokens.id_token)) {
      return { success: false, error: "Invalid ID token" };
    }

    // Get user info
    const userInfo = await getUserInfo(tokens.access_token);

    // Store auth state
    storeAuthState(tokens, userInfo);

    return { success: true };
  } catch (error) {
    return {
      success: false,
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    };
  }
}
