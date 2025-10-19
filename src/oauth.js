'use strict';

const {fetch} = require('@adobe/fetch');

class OAuthClient {
    constructor({fetch: customFetch, appBuild, userAgent, timeZone, clientId, scope, tokenStore}) {
        this.fetch = customFetch || fetch;
        this.appBuild = appBuild;
        this.userAgent = userAgent;
        this.timeZone = timeZone;
        this.clientId = clientId || 'ios';
        this.scope = scope || 'client';
        this.tokenStore = tokenStore || {};
    }

    async refreshWithRefreshToken() {
        if (!this.tokenStore?.refreshToken) {
            throw new Error('Missing OAuth refresh token.');
        }
        const body = new URLSearchParams({
            client_id: this.clientId,
            grant_type: 'refresh_token',
            refresh_token: this.tokenStore.refreshToken,
            scope: this.scope,
        });
        const headers = {
            'APP-BUILD': this.appBuild,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cache-Control': 'no-cache',
            'X-Blink-Time-Zone': this.timeZone,
            'User-Agent': this.userAgent,
        };
        const res = await this.fetch('https://api.oauth.blink.com/oauth/token/', {
            method: 'POST',
            headers,
            body: body.toString(),
        });
        const text = res && await res.text();
        let payload;
        try {
            payload = text ? JSON.parse(text) : {};
        }
        catch (err) {
            throw new Error(`OAuth refresh failed (${res?.status}): ${text || err.message}`);
        }
        if (res.status !== 200) {
            throw new Error(`OAuth refresh failed (${res.status}): ${text}`);
        }
        this.tokenStore.accessToken = payload.access_token;
        if (payload.refresh_token) {
            this.tokenStore.refreshToken = payload.refresh_token;
        }
        const expiresIn = Number(payload.expires_in) || 3600;
        this.tokenStore.accessTokenExpiresAt = Date.now() + expiresIn * 1000;
        return true;
    }

    async authorizeWithPKCE() {
        if (process.env.ENABLE_PKCE === 'true') {
            throw new Error('PKCE flow requires client onboarding configuration.');
        }
        throw new Error('PKCE disabled: requires client onboarding');
    }
}

module.exports = {OAuthClient};
