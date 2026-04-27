import { betterFetch } from "@better-fetch/fetch";
import type { OAuth2Tokens, OAuthProvider, ProviderOptions } from "../oauth2";
import { createAuthorizationURL } from "../oauth2";

const OAUTH_SCOPE_SPLIT_RE = /\s+/;

interface FeishuEndpoints {
	authorizationEndpoint: string;
	tokenEndpoint: string;
	userInfoEndpoint: string;
}

interface FeishuTokenData {
	access_token?: string | undefined;
	expires_in?: number | undefined;
	refresh_token?: string | undefined;
	refresh_token_expires_in?: number | undefined;
	scope?: string | undefined;
	token_type?: string | undefined;
}

interface FeishuTokenResponse extends FeishuTokenData {
	code?: number | undefined;
	msg?: string | undefined;
	error?: string | undefined;
	error_description?: string | undefined;
	data?: FeishuTokenData | undefined;
}

/**
 * Feishu/Lark user profile information.
 *
 * @see https://open.feishu.cn/document/server-docs/authentication-management/login-state-management/get
 */
export interface FeishuProfile extends Record<string, unknown> {
	code: number;
	msg?: string | undefined;
	data?: {
		/** User display name */
		name?: string | undefined;
		/** User English display name */
		en_name?: string | undefined;
		/** User avatar URL */
		avatar_url?: string | undefined;
		/** User thumbnail avatar URL */
		avatar_thumb?: string | undefined;
		/** User middle-size avatar URL */
		avatar_middle?: string | undefined;
		/** User large avatar URL */
		avatar_big?: string | undefined;
		/** User's unique Open ID */
		open_id?: string | undefined;
		/** User's Union ID across apps from the same developer */
		union_id?: string | undefined;
		/** User's app-scoped User ID */
		user_id?: string | undefined;
		/** User email, if granted */
		email?: string | undefined;
		/** User enterprise email, if granted */
		enterprise_email?: string | undefined;
		/** User mobile number, if granted */
		mobile?: string | undefined;
	};
}

export interface FeishuOptions extends ProviderOptions<FeishuProfile> {
	/**
	 * Feishu/Lark App ID.
	 */
	clientId: string;
	/**
	 * Feishu/Lark App Secret.
	 */
	clientSecret: string;
}

const feishuEndpoints: FeishuEndpoints = {
	authorizationEndpoint:
		"https://accounts.feishu.cn/open-apis/authen/v1/authorize",
	tokenEndpoint: "https://open.feishu.cn/open-apis/authen/v2/oauth/token",
	userInfoEndpoint: "https://open.feishu.cn/open-apis/authen/v1/user_info",
};

const larkEndpoints: FeishuEndpoints = {
	authorizationEndpoint:
		"https://accounts.larksuite.com/open-apis/authen/v1/authorize",
	tokenEndpoint: "https://open.larksuite.com/open-apis/authen/v2/oauth/token",
	userInfoEndpoint: "https://open.larksuite.com/open-apis/authen/v1/user_info",
};

function getTokenData(response: FeishuTokenResponse) {
	return response.data || response;
}

function getTokenError(response: FeishuTokenResponse) {
	return (
		response.error_description ||
		response.error ||
		response.msg ||
		`OAuth token request failed with code ${response.code}`
	);
}

async function requestToken({
	options,
	tokenEndpoint,
	body,
}: {
	options: FeishuOptions;
	tokenEndpoint: string;
	body: Record<string, string>;
}) {
	const { data, error } = await betterFetch<FeishuTokenResponse>(
		tokenEndpoint,
		{
			method: "POST",
			headers: {
				"content-type": "application/json; charset=utf-8",
			},
			body: JSON.stringify({
				client_id: options.clientId,
				client_secret: options.clientSecret,
				...body,
			}),
		},
	);

	if (error || !data || (data.code !== undefined && data.code !== 0)) {
		throw new Error(
			`Failed to request Feishu/Lark OAuth token: ${
				data ? getTokenError(data) : error?.message || "Unknown error"
			}`,
		);
	}

	const tokenData = getTokenData(data);
	if (!tokenData.access_token) {
		throw new Error("Failed to request Feishu/Lark OAuth token: Missing token");
	}

	const tokens: OAuth2Tokens = {
		accessToken: tokenData.access_token,
		refreshToken: tokenData.refresh_token,
		tokenType: tokenData.token_type,
		scopes: tokenData.scope
			?.split(OAUTH_SCOPE_SPLIT_RE)
			.filter((scope) => scope.length > 0),
		raw: data as Record<string, unknown>,
	};

	if (tokenData.expires_in !== undefined) {
		tokens.accessTokenExpiresAt = new Date(
			Date.now() + tokenData.expires_in * 1000,
		);
	}

	if (tokenData.refresh_token_expires_in !== undefined) {
		tokens.refreshTokenExpiresAt = new Date(
			Date.now() + tokenData.refresh_token_expires_in * 1000,
		);
	}

	return tokens;
}

function createFeishuProvider({
	id,
	name,
	endpoints,
	options,
}: {
	id: "feishu" | "lark";
	name: string;
	endpoints: FeishuEndpoints;
	options: FeishuOptions;
}) {
	return {
		id,
		name,
		createAuthorizationURL({ state, scopes, codeVerifier, redirectURI }) {
			const _scopes: string[] = [];
			if (options.scope) _scopes.push(...options.scope);
			if (scopes) _scopes.push(...scopes);
			return createAuthorizationURL({
				id,
				options,
				authorizationEndpoint: endpoints.authorizationEndpoint,
				scopes: _scopes.length > 0 ? _scopes : undefined,
				state,
				codeVerifier,
				redirectURI,
				prompt: options.prompt,
			});
		},
		validateAuthorizationCode: async ({ code, codeVerifier, redirectURI }) => {
			const body: Record<string, string> = {
				grant_type: "authorization_code",
				code,
				redirect_uri: options.redirectURI || redirectURI,
			};
			if (codeVerifier) body.code_verifier = codeVerifier;
			return requestToken({
				options,
				tokenEndpoint: endpoints.tokenEndpoint,
				body,
			});
		},
		refreshAccessToken: options.refreshAccessToken
			? options.refreshAccessToken
			: async (refreshToken) => {
					return requestToken({
						options,
						tokenEndpoint: endpoints.tokenEndpoint,
						body: {
							grant_type: "refresh_token",
							refresh_token: refreshToken,
						},
					});
				},
		async getUserInfo(token) {
			if (options.getUserInfo) {
				return options.getUserInfo(token);
			}

			const { data: profile, error } = await betterFetch<FeishuProfile>(
				endpoints.userInfoEndpoint,
				{
					headers: {
						authorization: `Bearer ${token.accessToken}`,
					},
				},
			);

			if (error || !profile || profile.code !== 0 || !profile.data) {
				return null;
			}

			const data = profile.data;
			const openId = data.open_id;
			if (!openId) {
				return null;
			}

			const userMap = await options.mapProfileToUser?.(profile);
			const email = data.email || data.enterprise_email || null;
			return {
				user: {
					id: data.union_id || openId,
					name: data.name || data.en_name || openId,
					email,
					image:
						data.avatar_url ||
						data.avatar_big ||
						data.avatar_middle ||
						data.avatar_thumb,
					emailVerified: false,
					...userMap,
				},
				data: profile,
			};
		},
		options,
	} satisfies OAuthProvider<FeishuProfile, FeishuOptions>;
}

export const feishu = (options: FeishuOptions) => {
	return createFeishuProvider({
		id: "feishu",
		name: "Feishu",
		endpoints: feishuEndpoints,
		options,
	});
};

export const lark = (options: FeishuOptions) => {
	return createFeishuProvider({
		id: "lark",
		name: "Lark",
		endpoints: larkEndpoints,
		options,
	});
};
