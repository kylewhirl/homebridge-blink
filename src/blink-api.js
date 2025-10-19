/* eslint-disable require-jsdoc */
const crypto = require('crypto');
const {fetch, reset} = require('@adobe/fetch');

const {sleep} = require('./utils');
const IniFile = require('./inifile');
const {log} = require('./log');
const {stringify} = require('./stringify');
const {OAuthClient} = require('./oauth');
// const stringify = JSON.stringify;
// crypto.randomBytes(16).toString("hex").toUpperCase().replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, "$1-$2-$3-$4-$5")
const DEFAULT_BLINK_CLIENT_UUID = '1EAF7C88-2AAB-BC51-038D-DB96D6EEE22F';
const BLINK_API_HOST = 'immedia-semi.com';
const CACHE = new Map();
const BLINK_APP_BUILD = process.env.BLINK_APP_BUILD || 'IOS_2509241604';
const BLINK_USER_AGENT = process.env.BLINK_UA || 'Blink/2509241604 CFNetwork/3826.600.41 Darwin/24.6.0';
const BLINK_APP_VERSION = process.env.BLINK_APP_VERSION || '6.24.0 (2509241604)';
const DEFAULT_TIME_ZONE = process.env.BLINK_TZ || 'America/Los_Angeles';

const DEFAULT_CLIENT_OPTIONS = {
    notificationKey: null,
    device: 'iPhone15,3',
    type: 'ios',
    name: 'Homebridge',
    appVersion: BLINK_APP_VERSION,
    appBuild: BLINK_APP_BUILD,
    userAgent: BLINK_USER_AGENT,
    os: '17.5',
};

/* eslint-disable */
/**
 * https://github.com/MattTW/BlinkMonitorProtocol
 *
 * List of APIs as of 2022-03
 * /account/delete/
 * /api/v5/account/login
 * /api/v1/account/options
 * /api/v4/account/password_change/
 * /api/v4/account/password_change/pin/generate/
 * /api/v4/account/password_change/pin/verify/
 * /api/v6/account/register
 * /account/system_offline/{network}
 * /api/v1/account/tiv
 * /account/update
 * /api/v3/account/validate_email
 * /api/v3/account/validate_password
 * /api/v1/account/video_options
 * /api/v4/account/{accountId}/client/{clientId}/logout/
 * /api/v4/account/{accountId}/client/{clientId}/email_change/
 * /api/v4/account/{accountId}/client/{clientId}/email_change/pin/resend
 * /api/v4/account/{accountId}/client/{clientId}/email_change/pin/verify/
 * /api/v4/account/{accountId}/client/{clientId}/password_change/
 * /api/v4/account/{accountId}/client/{clientId}/password_change/pin/generate/
 * /api/v4/account/{accountId}/client/{clientId}/password_change/pin/verify/
 * /api/v4/account/{accountId}/client/{client}/pin/resend/
 * /api/v4/account/{accountId}/client/{client}/pin/verify/
 * /api/v4/account/{accountId}/pin/resend/
 * /api/v4/account/{accountId}/pin/verify/
 * /api/v3/account/{account_id}}/resend_account_verification/
 * /api/v1/accounts/{accountId}/clients/{clientId}/control_panel/pin/resend
 * /api/v1/accounts/{accountId}/clients/{clientId}/control_panel/pin/verify/
 * /api/v1/accounts/{accountId}/clients/{clientId}/control_panel/request_pin/
 * /api/v1/accounts/{accountId}/clients/{client_id}/control_panel/clients
 * /api/v1/accounts/{accountId}/clients/{client_id}/control_panel/delete
 * /api/v1/accounts/{accountId}/clients/{client}/options
 * /api/v1/accounts/{accountId}/country/update/
 * /api/v1/accounts/{accountId}/doorbells/{serial}/fw_update
 * /api/v1/accounts/{accountId}/events/app/
 * /api/v3/accounts/{accountId}/homescreen
 * /api/v1/accounts/{accountId}/info/
 * /api/v2/accounts/{accountId}/media/changed
 * /api/v1/accounts/{accountId}/media/delete
 * /api/v1/accounts/{accountId}/networks/{networkId}/cameras/{camera}/accessories/{accessoryType}/{accessoryId}/delete/
 * /api/v1/accounts/{accountId}/networks/{networkId}/cameras/{camera}/accessories/{accessoryType}/{accessoryId}/lights/{lightControl}
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/change_wifi
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/config
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/delete
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/status
 * /api/v1/accounts/{accountId}/networks/{networkId}/owls/{owlId}/thumbnail
 * /api/v1/accounts/{accountId}/networks/{networkId}/state/{type}
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/change_mode
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/change_wifi
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/clear_creds/
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/owl_as_chime/list
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/owl_as_chime/update
 * /api/v1/accounts/{accountId}/networks/{network_id}/doorbells/{doorbell_id}/stay_awake/
 * /api/v1/accounts/{accountId}/networks/{network_id}/state/disarm
 * /api/v5/accounts/{accountId}/networks/{network}/cameras/{camera}/liveview
 * /api/v1/accounts/{accountId}/networks/{network}/cameras/{camera}/zones
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/add
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/chime/{chimeType}/config
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/config
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/power_test
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{doorbell}/trigger_chime
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/config
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/delete
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/disable
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/enable
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/liveview
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/status
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/thumbnail
 * /api/v1/accounts/{accountId}/networks/{network}/doorbells/{lotus}/zones
 * /api/v1/accounts/{accountId}/networks/{network}/owls/add
 * /api/v1/accounts/{accountId}/networks/{network}/owls/{owl}/liveview
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/eject
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/format
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/request/{command}
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/request
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/{manifestId}/clip/delete/{clipId}
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/manifest/{manifestId}/clip/request/{clipId}
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/mount
 * /api/v1/accounts/{accountId}/networks/{network}/sync_modules/{moduleId}/local_storage/status
 * /api/v1/accounts/{accountId}/owls/{serial}/fw_update
 * /api/v1/accounts/{accountId}/subscriptions/clear_popup/{type}
 * /api/v2/accounts/{accountId}/subscriptions/entitlements
 * /api/v1/accounts/{accountId}/subscriptions/link/link_account
 * /api/v1/accounts/{accountId}/subscriptions/link/unlink_account
 * /api/v1/accounts/{accountId}/subscriptions/plans/cancel_trial
 * /api/v1/accounts/{accountId}/subscriptions/plans/get_device_attach_eligibility
 * /api/v1/accounts/{accountId}/subscriptions/plans/renew_trial
 * /api/v1/accounts/{accountId}/subscriptions/plans/{subscription_id}/attach
 * /api/v1/accounts/{accountId}/subscriptions/plans/{subscription}
 * /api/v2/accounts/{accountId}/subscriptions/plans
 * /api/v1/accounts/{accountId}/subscriptions/request/status/{uuid}
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/client_verification/pin/resend/
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/client_verification/pin/verify/
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/phone_number_change/
 * /api/v5/accounts/{accountId}/users/{user_id}/clients/{client_id}/phone_number_change/pin/verify
 * /app/logs/upload/
 * /api/v1/camera/usage
 * /client/{client_id}/update
 * /api/v1/countries/
 * /api/v2/devices/identify/{serialNumber}
 * /api/v1/feature_flags/enabled/
 * /api/v1/fw/app/update_check
 * /network/add
 * /network/{network}/camera/add
 * /api/v1/network/{network}/camera/{camera}/calibrate
 * /network/{network}/camera/{camera}/config
 * /network/{network}/camera/{camera}/delete/
 * /network/{network}/camera/{camera}/status
 * /api/v1/network/{network}/camera/{camera}/temp_alert_disable
 * /api/v1/network/{network}/camera/{camera}/temp_alert_enable
 * /network/{network}/camera/{camera}/thumbnail
 * /network/{network}/camera/{camera}/update
 * /network/{network}/camera/{camera}/{type}
 * /network/{network}/command/{command}/done/
 * /network/{network}/command/{command}/update/
 * /network/{network}/command/{command}
 * /network/{network}/delete
 * /api/v2/network/{network}/sync_module/{type}
 * /network/{network}/syncmodule/{syncmodule}/delete/
 * /network/{network}/update
 * /api/v1/networks/{network}/programs/create
 * /api/v1/networks/{network}/programs/{program}/delete
 * /api/v1/networks/{network}/programs/{program}/disable
 * /api/v1/networks/{network}/programs/{program}/enable
 * /api/v1/networks/{network}/programs/{program}/update
 * /api/v1/networks/{network}/programs
 * /api/v1/networks/{network}/sirens/activate/
 * /api/v1/networks/{network}/sirens/add/
 * /api/v1/networks/{network}/sirens/deactivate/
 * /api/v1/networks/{network}/sirens/
 * /api/v1/networks/{network}/sirens/update
 * /api/v1/networks/{network}/sirens/{siren}/activate/
 * /api/v1/networks/{network}/sirens/{siren}/delete
 * /api/v1/networks/{network}/sirens/{siren}/update
 * /api/v2/notification
 * /regions
 * /api/v1/sirens/
 * /api/v2/support/ob_phone/
 * /api/v1/sync_modules/{serial}/fw_update
 * /api/v1/users/{user_id}/country/update/
 * /api/v1/version
 */
/* eslint-enable */

class BlinkAPI {
    constructor(clientUUID, auth = {path: '~/.blink', section: 'default'}) {
        auth = auth || {};
        const authPath = process.env.BLINK || auth.path;
        const authSection = process.env.BLINK_SECTION || auth.section;
        const ini = IniFile.read(authPath, authSection);

        const parseJSON = value => {
            if (!value) return {};
            if (typeof value === 'object') return value;
            try {
                return JSON.parse(value);
            }
            catch (err) {
                log.debug(`Failed to parse JSON config: ${err.message}`);
                return {};
            }
        };
        const lookupIni = (...keys) => {
            if (!ini) return undefined;
            for (const key of keys) {
                if (!key) continue;
                if (ini[key] !== undefined) return ini[key];
                const normalized = key.replace(/\./g, '_');
                if (ini[normalized] !== undefined) return ini[normalized];
            }
            return undefined;
        };
        const parseBool = value => {
            if (typeof value === 'boolean') return value;
            if (typeof value === 'string') {
                if (/^(true|yes|1)$/i.test(value)) return true;
                if (/^(false|no|0)$/i.test(value)) return false;
            }
            return undefined;
        };

        const iniOAuth = parseJSON(lookupIni('oauth'));
        const iniAppIdentity = parseJSON(lookupIni('appIdentity'));

        const authConfig = auth.credentials || auth;

        this.authPath = authPath;
        this.authSection = authSection;
        this.auth = {
            email: process.env.BLINK_EMAIL ?? authConfig.email ?? lookupIni('email'),
            password: process.env.BLINK_PASSWORD ?? authConfig.password ?? lookupIni('password'),
            pin: process.env.BLINK_PIN ?? authConfig.pin ?? lookupIni('pin'),
            clientUUID: clientUUID || process.env.BLINK_CLIENT_UUID || authConfig.clientUUID ||
                lookupIni('client') || DEFAULT_BLINK_CLIENT_UUID,
            notificationKey: process.env.BLINK_NOTIFICATION_KEY ?? authConfig.notificationKey ??
                lookupIni('notification') ?? crypto.randomBytes(32).toString('hex'),
        };

        this.clientOptions = Object.assign({}, DEFAULT_CLIENT_OPTIONS, auth.clientOptions || {});
        this.clientOptions.notificationKey = this.auth.notificationKey;

        this.appIdentity = Object.assign({
            appBuild: iniAppIdentity.appBuild || this.clientOptions.appBuild || BLINK_APP_BUILD,
            userAgent: iniAppIdentity.userAgent || this.clientOptions.userAgent || BLINK_USER_AGENT,
            timeZone: iniAppIdentity.timeZone || DEFAULT_TIME_ZONE,
        }, auth.appIdentity || {});

        this.clientOptions.appBuild = this.appIdentity.appBuild;
        this.clientOptions.userAgent = this.appIdentity.userAgent;

        this.preferOAuth = parseBool(auth.preferOAuth);
        if (this.preferOAuth === undefined) this.preferOAuth = parseBool(lookupIni('preferOAuth'));
        if (this.preferOAuth === undefined) this.preferOAuth = true;

        this.enableLegacyLogin = parseBool(auth.enableLegacyLogin);
        if (this.enableLegacyLogin === undefined) this.enableLegacyLogin = parseBool(lookupIni('enableLegacyLogin'));
        if (this.enableLegacyLogin === undefined) this.enableLegacyLogin = true;

        const refreshToken = process.env.BLINK_REFRESH_TOKEN ??
            (auth.oauth && auth.oauth.refreshToken) ??
            lookupIni('oauth.refreshToken', 'oauth_refreshToken', 'refresh_token') ??
            iniOAuth.refreshToken;

        const accessToken = auth.accessToken ?? lookupIni('access_token') ?? iniOAuth.accessToken;
        const expiresAt = Number(auth.accessTokenExpiresAt ??
            lookupIni('access_token_expires_at') ?? iniOAuth.accessTokenExpiresAt) || 0;

        this.tokenStore = {
            accessToken: accessToken || null,
            accessTokenExpiresAt: expiresAt,
            refreshToken: refreshToken || null,
        };

        const oauthClientId = (auth.oauth && auth.oauth.clientId) || iniOAuth.clientId || 'ios';
        const oauthScope = (auth.oauth && auth.oauth.scope) || iniOAuth.scope || 'client';

        this.oauth = new OAuthClient({
            fetch,
            appBuild: this.appIdentity.appBuild,
            userAgent: this.appIdentity.userAgent,
            timeZone: this.appIdentity.timeZone,
            clientId: oauthClientId,
            scope: oauthScope,
            tokenStore: this.tokenStore,
        });

        const storedRegion = auth.region || lookupIni('region', 'tier');
        this.region = storedRegion || 'prod';

        this.authMode = (this.preferOAuth && this.tokenStore.refreshToken) ? 'oauth' : 'legacy';
        if (this.authMode === 'oauth') {
            this.token = null;
        }
        this._legacyNoticeLogged = false;
        this._lastLegacyLoginResponse = null;
        this._forceLegacyLogin = false;
        this._legacyLoginHttpErrorAsError = undefined;
    }

    set region(val) {
        if (val) this._region = val;
    }

    get region() {
        return this._region || 'prod';
    }

    set token(val) {
        this._token = val || null;
    }

    get token() {
        return this._token;
    }

    set accountID(val) {
        if (val) this._accountID = val;
    }

    get accountID() {
        return this._accountID;
    }

    set clientID(val) {
        if (val) this._clientID = val;
    }

    get clientID() {
        return this._clientID;
    }

    set authMode(val) {
        if (!val) return;
        this._authMode = val;
        if (val === 'oauth') {
            this._token = null;
        }
    }

    get authMode() {
        return this._authMode || 'legacy';
    }

    init(token, accountID, clientID, region = 'prod') {
        this.token = token;
        this.accountID = accountID;
        this.clientID = clientID;
        this.region = region;
    }

    async reset() {
        return reset();
    }

    async get(path = '/', maxTTL = 1, autologin = true, httpErrorAsError = true) {
        return await this._request('GET', path, null, maxTTL, autologin, httpErrorAsError);
    }

    async post(path = '/', body = null, autologin = true, httpErrorAsError = true) {
        return this._request('POST', path, body, null, autologin, httpErrorAsError);
    }

    async _request(method = 'GET', path = '/', body = null, maxTTL = null, autologin = true,
        httpErrorAsError = true, retrying = false) {
        if (autologin) await this.ensureSession();
        const targetPath = this._expandPath(path);

        if (CACHE.has(method + targetPath) && maxTTL > 0) {
            const cache = CACHE.get(method + targetPath);
            const lastModified = Date.parse(cache.headers.get('last-modified') || cache.headers.get('date') || 0);
            if (lastModified + (maxTTL * 1000) > Date.now()) {
                return cache._body;
            }
            cache.headers.set('last-modified', (new Date(Date.now() + 3 * 1000)).toISOString());
        }

        const headers = this._buildRequestHeaders(body);
        const options = {method, headers};
        if (body !== null && body !== undefined) {
            options.body = typeof body === 'string' ? body : JSON.stringify(body);
        }

        log.info(`${method} ${targetPath} @${maxTTL}`);
        log.debug(options);
        const urlPrefix = this._resolveUrl(targetPath);
        let res;
        try {
            res = await fetch(`${urlPrefix}${targetPath}`, options);
        }
        catch (e) {
            if (!/ECONNRESET|ETIMEDOUT|ESOCKETTIMEDOUT|disconnected/i.test(e.message)) log.error(e);
            if (autologin) {
                await sleep(500);
                return this._request(method, path, body, maxTTL, false, httpErrorAsError, retrying);
            }
            throw e;
        }

        if (!res) {
            if (autologin) {
                await sleep(500);
                return this._request(method, path, body, maxTTL, false, httpErrorAsError, retrying);
            }
            throw new Error('Blink API request failed with no response');
        }

        log.debug(res.status + ' ' + res.statusText);
        if (res.headers?.entries) {
            try {
                log.debug(Object.fromEntries(res.headers.entries()));
            }
            catch (_) {
                // ignore header logging failures
            }
        }

        await this._captureBody(res);

        if (res.status === 401) {
            if (this.authMode === 'oauth' && !retrying) {
                await this._refreshAccessToken();
                return this._request(method, path, body, maxTTL, false, httpErrorAsError, true);
            }
            if (this.authMode === 'legacy' && autologin && !retrying) {
                this.token = null;
                await this.ensureSession();
                return this._request(method, path, body, maxTTL, false, httpErrorAsError, true);
            }
            return this._handleHttpError(res, method, targetPath, httpErrorAsError);
        }

        if (res.status === 426) {
            return this._handleHttpError(res, method, targetPath, true);
        }

        if (res.status >= 500) {
            const statusLabel = this._statusLabel(res);
            log.error(`RETRY: ${method} ${targetPath} (${statusLabel})`);
            if (this.authMode === 'legacy') this.token = null;
            if (!retrying) {
                await sleep(1000);
                return this._request(method, path, body, maxTTL, false, httpErrorAsError, true);
            }
            return this._handleHttpError(res, method, targetPath, httpErrorAsError);
        }

        if (res.status === 429) {
            const statusLabel = this._statusLabel(res);
            log.error(`RETRY: ${method} ${targetPath} (${statusLabel})`);
            if (!retrying) {
                await sleep(500);
                return this._request(method, path, body, maxTTL, false, httpErrorAsError, true);
            }
            return this._handleHttpError(res, method, targetPath, httpErrorAsError);
        }

        if (res.status === 409) {
            if (httpErrorAsError) {
                if (!/busy/i.test(res?._body?.message)) {
                    return this._handleHttpError(res, method, targetPath, httpErrorAsError);
                }
            }
        }
        else if (res.status >= 400) {
            return this._handleHttpError(res, method, targetPath, httpErrorAsError);
        }

        if (method === 'GET') {
            CACHE.set(method + targetPath, res);
        }

        if (method !== 'GET') {
            CACHE.delete('GET' + path);
        }
        return res._body;
    }

    async ensureSession() {
        if (this.authMode === 'oauth') {
            if (!this.tokenStore.refreshToken) {
                if (this.preferOAuth && !this._legacyNoticeLogged) {
                    log.info('Blink legacy login in use; add an OAuth refresh token to enable OAuth authentication.');
                    this._legacyNoticeLogged = true;
                }
                if (this.enableLegacyLogin) {
                    this.authMode = 'legacy';
                    return this.ensureSession();
                }
                throw new Error('No OAuth refresh token configured and legacy login disabled.');
            }
            const expiresAt = Number(this.tokenStore.accessTokenExpiresAt) || 0;
            const expiresSoon = !this.tokenStore.accessToken || Date.now() > (expiresAt - 60000);
            if (expiresSoon) {
                await this._refreshAccessToken();
            }
            this.token = null;
            this._forceLegacyLogin = false;
            this._legacyLoginHttpErrorAsError = undefined;
            return;
        }

        if (!this.enableLegacyLogin) {
            throw new Error('Legacy login disabled.');
        }

        if (this.preferOAuth && !this.tokenStore.refreshToken && !this._legacyNoticeLogged) {
            log.info('Blink legacy login in use; add an OAuth refresh token to enable OAuth authentication.');
            this._legacyNoticeLogged = true;
        }

        const httpErrorAsError = this._legacyLoginHttpErrorAsError ?? true;
        const forceLogin = this._forceLegacyLogin || !this.token;
        if (forceLogin) {
            try {
                await this.loginLegacy(forceLogin, this.clientOptions, httpErrorAsError);
            }
            finally {
                this._forceLegacyLogin = false;
                this._legacyLoginHttpErrorAsError = undefined;
            }
        }
        else {
            this._forceLegacyLogin = false;
            this._legacyLoginHttpErrorAsError = undefined;
        }
    }

    async login(force = false, client = DEFAULT_CLIENT_OPTIONS, httpErrorAsError = true) {
        if (client) {
            this.clientOptions = Object.assign({}, DEFAULT_CLIENT_OPTIONS, client || {});
            this.clientOptions.notificationKey = this.auth.notificationKey;
        }

        if (this.authMode === 'legacy') {
            this._legacyLoginHttpErrorAsError = httpErrorAsError;
            this._forceLegacyLogin = force;
            await this.ensureSession();
            return this._lastLegacyLoginResponse;
        }

        if (!this.tokenStore.refreshToken && this.enableLegacyLogin) {
            this._legacyLoginHttpErrorAsError = httpErrorAsError;
            this._forceLegacyLogin = force;
        }

        if (force) {
            this.tokenStore.accessToken = null;
            this.tokenStore.accessTokenExpiresAt = 0;
        }

        await this.ensureSession();

        if (this.authMode === 'legacy') {
            return this._lastLegacyLoginResponse;
        }

        return {
            auth: {token: this.tokenStore.accessToken},
            account: {
                account_id: this.accountID,
                client_id: this.clientID,
                tier: this.region,
            },
        };
    }

    async loginLegacy(force = false, client = this.clientOptions, httpErrorAsError = true) {
        if (!this.enableLegacyLogin) {
            throw new Error('Legacy login is disabled.');
        }
        if (!force && this.token) return this._lastLegacyLoginResponse;
        if (!this.auth?.email || !this.auth?.password) {
            throw new Error('Email or Password is blank');
        }

        const clientOptions = Object.assign({}, DEFAULT_CLIENT_OPTIONS, client || {});
        clientOptions.notificationKey = clientOptions.notificationKey || this.auth.notificationKey;
        clientOptions.appBuild = clientOptions.appBuild || this.appIdentity.appBuild;
        clientOptions.userAgent = clientOptions.userAgent || this.appIdentity.userAgent;
        clientOptions.appVersion = clientOptions.appVersion || BLINK_APP_VERSION;
        clientOptions.os = clientOptions.os || '17.5';
        this.clientOptions = clientOptions;

        const data = {
            'app_version': clientOptions.appVersion,
            'client_name': clientOptions.name,
            'client_type': clientOptions.type,
            'device_identifier': clientOptions.device,
            'email': this.auth.email,
            'notification_key': clientOptions.notificationKey,
            'os_version': clientOptions.os,
            'password': this.auth.password,
            'unique_id': this.auth.clientUUID,
            'app_build': clientOptions.appBuild,
        };
        if (this.auth.pin) data.reauth = 'true';

        const headers = this._buildBaseHeaders();
        headers['Content-Type'] = 'application/json';
        const url = `https://rest-${this.region || 'prod'}.${BLINK_API_HOST}/api/v5/account/login`;
        const res = await fetch(url, {method: 'POST', headers, body: JSON.stringify(data)});

        await this._captureBody(res);

        if (res.status === 426) {
            const details = this._stringifyBody(res._body);
            throw new Error(`Legacy login rejected with 426 Upgrade Required${details ? `: ${details}` : ''}`);
        }
        if (!res.ok) {
            return this._handleHttpError(res, 'POST', '/api/v5/account/login', httpErrorAsError);
        }

        const account = res._body?.account || {};
        this.init(res._body?.auth?.token, account.account_id || account.id, account.client_id, account.tier || this.region);
        this.authMode = 'legacy';
        this._lastLegacyLoginResponse = res._body;
        await this._maybeDiscoverRegion();
        this._persistTokens();
        return res._body;
    }

    async _maybeDiscoverRegion() {
        const endpoints = ['/api/v6/homescreen', '/api/v6/accounts/me/homescreen'];
        for (const endpoint of endpoints) {
            try {
                const result = await this._request('GET', endpoint, null, 0, false, false, true);
                if (result) {
                    this._applyRegionMetadata(result);
                    this._persistTokens();
                    return;
                }
            }
            catch (err) {
                if (err?.status && err.status !== 404) {
                    log.debug(`Region discovery failed via ${endpoint}: ${err.message}`);
                }
            }
        }
    }

    _applyRegionMetadata(payload) {
        if (!payload) return;
        const account = payload.account || payload.accounts?.[0];
        if (account) {
            const accountId = account.account_id || account.id;
            const clientId = account.client_id || account.clientID;
            if (accountId) this.accountID = accountId;
            if (clientId) this.clientID = clientId;
            if (account.tier) this.region = account.tier;
        }

        const regionInfo = payload.region || {};
        if (regionInfo.tier) this.region = regionInfo.tier;
        if (regionInfo.id) this.region = regionInfo.id;
        const restUrl = regionInfo.rest || regionInfo.dns || payload.rest_url || payload.rest_url_v6;
        const match = restUrl && /rest-([a-z0-9]+)/i.exec(restUrl);
        if (match && match[1]) this.region = match[1];
    }

    _persistTokens() {
        if (typeof IniFile.write !== 'function' || !this.authPath || !this.authSection) return;
        const data = {region: this.region};
        if (this.tokenStore.refreshToken) data.refresh_token = this.tokenStore.refreshToken;
        if (this.authMode === 'oauth') {
            if (this.tokenStore.accessToken) data.access_token = this.tokenStore.accessToken;
            if (this.tokenStore.accessTokenExpiresAt) {
                data.access_token_expires_at = this.tokenStore.accessTokenExpiresAt;
            }
        }
        try {
            IniFile.write(this.authPath, this.authSection, data);
        }
        catch (err) {
            log.debug(`Failed to persist tokens: ${err.message}`);
        }
    }

    _buildBaseHeaders() {
        return {
            'APP-BUILD': this.appIdentity.appBuild || BLINK_APP_BUILD,
            'User-Agent': this.appIdentity.userAgent || BLINK_USER_AGENT,
            'X-Blink-Time-Zone': this.appIdentity.timeZone || DEFAULT_TIME_ZONE,
            'Accept': '*/*',
            'Accept-Language': 'en_US',
            'Locale': 'en_US',
            'Cache-Control': 'no-cache',
        };
    }

    _buildRequestHeaders(body) {
        const headers = this._buildBaseHeaders();
        if (body !== null && body !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        if (this.authMode === 'oauth' && this.tokenStore.accessToken) {
            headers['Authorization'] = `Bearer ${this.tokenStore.accessToken}`;
        }
        else if (this.token) {
            headers['TOKEN_AUTH'] = this.token;
        }
        return headers;
    }

    _resolveUrl(targetPath) {
        return /^https?:/i.test(targetPath) ? '' : `https://rest-${this.region || 'prod'}.${BLINK_API_HOST}`;
    }

    _expandPath(path = '/') {
        let targetPath = path;
        if (this.accountID) targetPath = targetPath.replace('{accountID}', this.accountID);
        if (this.clientID) targetPath = targetPath.replace('{clientID}', this.clientID);
        return targetPath;
    }

    async _captureBody(res) {
        if (!res) return null;
        const contentType = res.headers?.get ? res.headers.get('content-type') || '' : '';
        if (/application\/json/i.test(contentType)) {
            const json = await res.json();
            res._body = json;
            log.debug(stringify(json));
            return json;
        }
        if (/text\//i.test(contentType)) {
            const text = await res.text();
            res._body = text;
            log.debug(text);
            return text;
        }
        if (typeof res.arrayBuffer === 'function') {
            const buffer = Buffer.from(await res.arrayBuffer());
            res._body = buffer;
            return buffer;
        }
        res._body = null;
        return null;
    }

    _statusLabel(res) {
        if (!res) return '';
        const header = res.headers && typeof res.headers.get === 'function' ? res.headers.get('status') : null;
        const statusText = `${res.status || ''} ${res.statusText || ''}`.trim();
        return header || statusText;
    }

    _handleHttpError(res, method, targetPath, httpErrorAsError) {
        const statusLabel = this._statusLabel(res);
        const body = res?._body;
        if (res?.status === 426) {
            const details = this._stringifyBody(body);
            const err = new Error(`Legacy login rejected with 426 Upgrade Required${details ? `: ${details}` : ''}`);
            err.status = res.status;
            throw err;
        }
        log.error(`${method} ${targetPath} (${statusLabel})`);
        if (body) log.error(body);
        if (!httpErrorAsError) return body;
        const error = new Error(`${method} ${targetPath} (${statusLabel})`);
        error.status = res?.status;
        error.response = body;
        throw error;
    }

    _stringifyBody(body) {
        if (!body) return '';
        if (typeof body === 'string') return body;
        try {
            return stringify(body);
        }
        catch (err) {
            try {
                return JSON.stringify(body);
            }
            catch (_) {
                return '';
            }
        }
    }

    async _refreshAccessToken() {
        await this.oauth.refreshWithRefreshToken();
        this.authMode = 'oauth';
        this._persistTokens();
        await this._maybeDiscoverRegion();
    }

    async getUrl(url) {
        return await this.get(`${url}`);
    }

    /**
     *
     * APP CLIENT FUNCTIONS
     *
     **/

    /**
     * POST https://rest-prod.immedia-semi.com/api/v4/account/1000001/client/2360401/pin/verify
     * :authority:       rest-prod.immedia-semi.com
     * locale:           en_CA
     * content-type:     application/json
     * accept:           * /*
     * app-build:        ANDROID_28373244
     * token-auth:       2YKEsy9BPb9puha1s4uBwe
     * accept-encoding:  gzip, deflate, br
     * user-agent:       27.0ANDROID_28373244
     * accept-language:  en-CA
     * content-length:   16
     * {"pin":"123456"}
     *
     * content-type:            application/json
     * date:                    Fri, 02 Oct 2020 00:26:48 GMT
     * vary:                    Accept-Encoding
     * status:                  200 OK
     * x-blink-served-by:       i-084c7f99a490e5cf5
     * x-content-type-options:  nosniff
     * x-powered-by:            Phusion Passenger
     * server:                  nginx + Phusion Passenger
     * content-encoding:        gzip
     * x-cache:                 Miss from cloudfront
     * via:                     1.1 2c060d2b820e53bf308fe03fbfaed0e9.cloudfront.net (CloudFront)
     * x-amz-cf-pop:            ATL56-C1
     * x-amz-cf-id:             lbxn02VW0vtzs3S0QnPnkjdnW5rTyja2ooPMSbQAI3jQjal2O-ynfQ==
     * {
     *     "code": 1626,
     *     "message": "Client has been successfully verified",
     *     "require_new_pin": false,
     *     "valid": true
     * }
     **/
    async verifyPIN(pin, httpAsError = true) {
        const data = {
            pin: pin || this.auth.pin,
        };
        return await this.post(`/api/v4/account/{accountID}/client/{clientID}/pin/verify/`, data, false, httpAsError);
    }

    async resendPIN(httpAsError = true) {
        return await this.post(`/api/v4/account/{accountID}/client/{clientID}/pin/resend/`, null, false, httpAsError);
    }

    async logout() {
        return await this.post(`/api/v4/account/{accountID}/client/{clientID}/logout/`);
    }

    /**
     * GET https: *rest-prod.immedia-semi.com/api/v1/accounts/1000001/clients/2360401/options
     * {
     *     "options": "eyJuZXR3b3JrX29yZGVyIjpbMTIwOTJd...hbWVyYV9vcmRlciI6eyIxMjA5MiI6WzM2Nzk5LDM2ODE3XX19"
     * }
     *
     * base64 decode:
     * {
     *     "network_order":    [2000001],
     *     "keys":    [
     *         ["client.options.show_homescreen_tutorial_state", "N1"],
     *         ["homescreen.whats_new_last_showed_at", "N20200902"],
     *         ["client.options.show_add_device_tutorial_state", "N1"]
     *     ],
     *     "schema": 1,
     *     "camera_order": {
     *         "2000001" : [4000001, 4000002]
     *     }
     * }
     **/
    async getClientOptions() {
        return await this.get(`/api/v1/accounts/{accountID}/clients/{clientID}/options`);
    }

    async updateClientOptions(clientOptionsResponse) {
        return await this.post(`/api/v1/accounts/{accountID}/clients/{clientID}/options`, clientOptionsResponse);
    }

    /**
     * ACCOUNT
     */

    /*
     *
     * {
     *   "account": {
     *     "id": 1000001,
     *     "email_verified": true,
     *     "email_verification_required": true
     *   },
     *   "networks": [
     *     {
     *       "id": 2000001,
     *       "created_at": "2016-02-13T19:15:54+00:00",
     *       "updated_at": "2020-10-02T00:29:30+00:00",
     *       "name": "82 Downing",
     *       "time_zone": "America/Toronto",
     *       "dst": true,
     *       "armed": false,
     *       "lv_save": false
     *     }
     *   ],
     *   "sync_modules": [
     *     {
     *       "id": 3000001,
     *       "created_at": "2016-02-13T19:17:57+00:00",
     *       "updated_at": "2020-10-03T04:35:46+00:00",
     *       "onboarded": true,
     *       "status": "online",
     *       "name": "Blink SM",
     *       "serial": "A0000001",
     *       "fw_version": "2.13.26",
     *       "type": "sm1",
     *       "last_hb": "2020-10-03T15:44:36+00:00",
     *       "wifi_strength": 1,
     *       "network_id": 2000001,
     *       "enable_temp_alerts": true,
     *       "local_storage_enabled": false,
     *       "local_storage_compatible": false,
     *       "local_storage_status": "unavailable"
     *     }
     *   ],
     *   "cameras": [
     *     {
     *       "id": 4000001,
     *       "created_at": "2016-02-13T19:21:09+00:00",
     *       "updated_at": "2020-10-03T14:50:36+00:00",
     *       "name": "Alpha",
     *       "serial": "B0000001",
     *       "fw_version": "2.151",
     *       "type": "white",
     *       "enabled": true,
     *       "thumbnail": "/media/production/account/101/network/2001/camera/4001/clip_HIwo6g_2020_10_02__00_28AM",
     *       "status": "done",
     *       "battery": "ok",
     *       "usage_rate": false,
     *       "network_id": 2000001,
     *       "issues": [],
     *       "signals": {
     *         "lfr": 5,
     *         "wifi": 5,
     *         "temp": 78,
     *         "battery": 3
     *       },
     *       "local_storage_enabled": false,
     *       "local_storage_compatible": false
     *     },
     *     {
     *       "id": 13812,
     *       "created_at": "2016-02-13T19:29:36+00:00",
     *       "updated_at": "2020-10-03T11:20:36+00:00",
     *       "name": "Beta",
     *       "serial": "130060596",
     *       "fw_version": "2.151",
     *       "type": "white",
     *       "enabled": true,
     *       "thumbnail": "/media/production/account/1001/network/2001/camera/13812/clip_rHLLGqU_2020_10_02__00_17AM",
     *       "status": "done",
     *       "battery": "ok",
     *       "usage_rate": false,
     *       "network_id": 2000001,
     *       "issues": [],
     *       "signals": {
     *         "lfr": 5,
     *         "wifi": 2,
     *         "temp": 65,
     *         "battery": 3
     *       },
     *       "local_storage_enabled": false,
     *       "local_storage_compatible": false
     *     }
     *   ],
     *   "sirens": [],
     *   "chimes": [],
     *   "video_stats": {
     *     "storage": 1,
     *     "auto_delete_days": 365,
     *     "auto_delete_day_options": [3,7,14,30,365]
     *   },
     *   "doorbell_buttons": [],
     *   "owls": [],
     *   "app_updates": {
     *     "message": "OK",
     *     "code": 103,
     *     "update_available": false,
     *     "update_required": false
     *   },
     *   "device_limits": {
     *     "camera": 10,
     *     "chime": 5,
     *     "doorbell_button": 2,
     *     "owl": 10,
     *     "siren": 5,
     *     "total_devices": 20
     *   },
     *   "whats_new": {
     *     "updated_at": 20200902,
     *     "url": "https: *updates.blinkforhome.com/"
     *   }
     * }
     */
    async getAccountHomescreen(maxTTL = 30) {
        return await this.get(`/api/v3/accounts/{accountID}/homescreen`, maxTTL);
    }

    /*
    {
        'id': 12147,
        'created_at': '2016-02-13T19:15:54+00:00',
        'updated_at': '2019-01-06T17:03:28+00:00',
        'email': 'user@example.com',
        'verified': true,
        'verification_required': true,
        'force_password_reset': false,
        'reset_expiration': null,
        'time_zone': 'US/Eastern',
        'owner': true,
        'name': '',
        'user_access': 'write',
        'temp_units': 'f',
        'type': 'regular',
        'pin_created_at': null,
        'pin_failures': 0,
        'account_id': 1000001,
    }
    */
    async getAccount() {
        return await this.get(`/user`);
    }

    /**
     *  {"account":{"id":1000001,"verification_required":false},"client":{"id":9000001,"verification_required":false}}
     */
    async getAccountStatus() {
        return await this.get(`/api/v3/account/{accountID}/status`);
    }

    /**
     * {
     *   "catalina_app_enabled":true,
     *   "sm2_app_enabled":true,
     *   "snapshot_app_enabled":true,
     *   "owl_app_enabled":true,
     *   "legacy_account_mini":true
     * }
     */
    async getAccountOptions() {
        return await this.get(`/api/v1/account/options`);
    }

    /*
    {
        'notifications': {
            'low_battery': true,
            'camera_offline': true,
            'camera_usage': true,
            'scheduling': true,
            'motion': true,
            'sync_module_offline': true,
            'temperature': true,
            'doorbell': true,
            'wifi': true,
            'lfr': true,
            'bandwidth': true,
            'battery_dead': true,
            'local_storage': true,
        },
    }
    */
    async getAccountNotifications() {
        return await this.get(`/api/v1/accounts/{accountID}/notifications/configuration`);
    }

    /**
     * {"notifications":{"camera_usage":true}}
     * {"message":"Client Notification Configure Update Successful"}
     */
    async updateAccountNotifications() {
        return await this.post(`/api/v1/accounts/{accountID}/notifications/configuration`);
    }

    async acknowledgeAccountNotification(notifications = {}) {
        return await this.post(`/api/v2/notification`, notifications);
    }

    async updateAccountVideoOptions(autoPurgeSetterBody) {
        return await this.post(`/api/v1/account/video_options`, autoPurgeSetterBody);
    }

    async updateAccountPassword(changePasswordBody) {
        return await this.post(`/account/change_password/`, changePasswordBody);
    }

    async deleteAccountPassword(resetPasswordBody) {
        return await this.post(`/account/reset_password/`, resetPasswordBody);
    }

    async createAccount(registerAccount) {
        return await this.post(`/api/v4/account/register`, registerAccount);
    }

    async updateAccount(updateAccountBody) {
        return await this.post(`/account/update`, updateAccountBody);
    }

    // async deleteAccount(deleteAccountBody) {
    //     return await this.post(`/account/delete/`, deleteAccountBody);
    // }

    /**
     * MEDIA
     */

    /**
     * {
     *   "limit": 25,
     *   "purge_id": 2139143115,
     *   "refresh_count": 0,
     *   "media": [
     *     {
     *       "id": 2139143346,
     *       "created_at": "2020-10-02T00:28:38+00:00",
     *       "updated_at": "2020-10-02T00:28:57+00:00",
     *       "deleted": false,
     *       "device": "camera",
     *       "device_id": 13812,
     *       "device_name": "Beta",
     *       "network_id": 2000001,
     *       "network_name": "82 Downing",
     *       "type": "video",
     *       "source": "pir",
     *       "watched": false,
     *       "partial": false,
     *       "thumbnail": "/api/v2/accounts/1000001/media/thumb/2139143346",
     *       "media": "/api/v2/accounts/1000001/media/clip/2139143346.mp4",
     *       "additional_devices": [],
     *       "time_zone": "America/Tortola"
     *     }
     *   ]
     * }
     **/
    async getMediaChange(maxTTL = 60, after = '1970-01-01T00:00:01+0000', page = 1) {
        const since = new Date(after);
        return await this.get(`/api/v1/accounts/{accountID}/media/changed?since=${since.toISOString()}&page=${page}`,
            maxTTL);
    }

    async deleteMedia(medialist = []) {
        if (!medialist || medialist.length === 0) return;
        if (!Array.isArray(medialist)) medialist = [medialist];
        return await this.post(`/api/v1/accounts/{accountID}/media/delete`, {media_list: medialist});
    }

    /**
     * COMMAND
     */

    async getCommand(networkID, commandID) {
        return await this.get(`/network/${networkID}/command/${commandID}`);
    }

    async updateCommand(networkID, commandID, updateCommandRequest) {
        return await this.post(`/network/${networkID}/command/${commandID}/update/`, updateCommandRequest);
    }

    async deleteCommand(networkID, commandID) {
        return await this.post(`/network/${networkID}/command/${commandID}/done/`);
    }

    /**
     * PROGRAMS
     */
    async getPrograms(networkID) {
        return await this.get(`/api/v1/networks/${networkID}/programs`);
    }

    /**
     *
     * {
     *     "format": "v1",
     *     "id": 105008,
     *     "name": "Schedule for 82 Downing",
     *     "schedule": [
     *         {
     *             "action": "arm",
     *             "devices": [],
     *             "dow": [
     *                 "sun",
     *                 "wed"
     *             ],
     *             "time": "2020-10-03 04:00:00 +0000"
     *         },
     *         {
     *             "action": "disarm",
     *             "devices": [],
     *             "dow": [
     *                 "sun",
     *                 "wed"
     *             ],
     *             "time": "2020-10-03 05:30:00 +0000"
     *         }
     *     ]
     * }
     **/
    async createProgram(networkID, program) {
        return await this.post(`/api/v1/networks/${networkID}/programs/create`, program);
    }

    async updateProgram(networkID, programID, updateProgramRequest) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${programID}/update`, updateProgramRequest);
    }

    async deleteProgram(networkID, prgoramID) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${prgoramID}/delete`);
    }

    async disableProgram(networkID, programID) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${programID}/disable`);
    }

    async enableProgram(networkID, programID) {
        return await this.post(`/api/v1/networks/${networkID}/programs/${programID}/enable`);
    }

    /**
     * CAMERA
     */

    /**
     * see: SAMPLE.CAMERA_CONFIG
     */
    async getCameraConfig(networkID, cameraID) {
        return await this.get(`/network/${networkID}/camera/${cameraID}/config`);
    }

    /**
     * see: SAMPLE.CAMERA_USAGE
     */
    async getCameraUsage() {
        return await this.get(`/api/v1/camera/usage`);
    }

    /**
     * see: SAMPLE.CAMERA_STATUS
     */
    async getCameraStatus(networkID, cameraID, maxTTL = 60 * 60) {
        return await this.get(`/network/${networkID}/camera/${cameraID}`, maxTTL);
    }

    /**
     * see: SAMPLE.UPDATE_THUMBNAIL
     */
    async updateCameraThumbnail(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/thumbnail`);
    }

    /**
     * see: SAMPLE.UPDATE_CLIP
     */
    async updateCameraClip(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/clip`);
    }

    async deleteCameraClip(clipID) {
        return await this.deleteMedia(clipID);
    }

    /**
     * see: SAMPLE.ENABLE_CAMERA
     */
    async enableCameraMotion(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/enable`);
    }

    /**
     * see: SAMPLE.DISABLE_CAMERA
     */
    async disableCameraMotion(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/disable`);
    }

    // async createCamera(networkID, addCameraBody) {
    //     return await this.post(`/network/${networkID}/camera/add`, addCameraBody);
    // }

    // async deleteCamera(networkID, cameraID) {
    //     return await this.post(`/network/${networkID}/camera/${cameraID}/delete/`);
    // }

    async getCameraMotionRegions(networkID, cameraID) {
        return await this.get(`/api/v1/accounts/{accountID}/networks/${networkID}/cameras/${cameraID}/motion_regions`);
    }

    /**
     * POST {"intent":"liveview","motion_event_start_time":""}
     * {
     *     "command_id": 1023787103,
     *     "continue_interval": 30,
     *     "continue_warning": 10,
     *     "duration": 300,
     *     "extended_duration": 5400,
     *     "join_available": true,
     *     "join_state": "available",
     *     "media_id": null,
     *     "new_command": true,
     *     "options": {},
     *     "polling_interval": 15,
     *     "server": "rtsps://lv2-app-prod.immedia-semi.com:443/iaRAwBZRD_R__IMDS_160060593?client_id=208&blinkRTSP=true",
     *     "submit_logs": true
     * }
     * {"command_id":750082091,"join_available":true,"join_state":"available",
     *   "server":"rtsps://lv2-app-prod.immedia-semi.com:443/NIE5YSJGOOOn__IMDS_B0000001?client_id=208&blinkRTSP=true",
     *   "duration":300,"continue_interval":30,"continue_warning":10,"submit_logs":true,"new_command":true,
     *   "media_id":null,"options":{}}
     * {"complete":false,"status":0,"status_msg":"Command succeeded","status_code":908,
     *   "commands":[{"id":750082091,"created_at":"2020-10-02T00:27:54+00:00","updated_at":"2020-10-02T00:27:56+00:00",
     *      "execute_time":"2020-10-02T00:27:54+00:00","command":"lv_relay","state_stage":"lv",
     *      "stage_rest":"2020-10-02T00:27:54+00:00","stage_cs_db":"2020-10-02T00:27:54+00:00",
     *      "stage_cs_sent":"2020-10-02T00:27:54+00:00","stage_sm":"2020-10-02T00:27:54+00:00",
     *       "stage_dev":"2020-10-02T00:27:56+00:00","stage_is":null,"stage_lv":"2020-10-02T00:27:56+00:00",
     *       "stage_vs":null,"state_condition":"running","sm_ack":1,"lfr_ack":0,"sequence":365,"attempts":0,
     *       "transaction":"NIE5Fm36YSJGOOOn","player_transaction":"mrkXahUbYjfbUgHg",
     *      "server":"rtsps://lv2-prod.immedia-semi.com:443/NIE5Fm36YSJGOOOn","duration":300,
     *      "by_whom":"unknown - 6.1.1 (8854) #e06341d7f - liveview","diagnostic":false,
     *      "debug":"{\"lfr_ok\":[2000001,1,365,205,151,159,167,0]}","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001
     *   }],
     *   "media_id":null
     * }
     * {"complete":true,"status":0,"status_msg":"Command succeeded","status_code":908,
     *  "commands":[{
     *      "id":750082091,"created_at":"2020-10-02T00:27:54+00:00","updated_at":"2020-10-02T00:27:56+00:00",
     *      "execute_time":"2020-10-02T00:27:54+00:00","command":"lv_relay","state_stage":"lv",
     *      "stage_rest":"2020-10-02T00:27:54+00:00","stage_cs_db":"2020-10-02T00:27:54+00:00",
     *      "stage_cs_sent":"2020-10-02T00:27:54+00:00","stage_sm":"2020-10-02T00:27:54+00:00",
     *      "stage_dev":"2020-10-02T00:27:56+00:00","stage_is":null,"stage_lv":"2020-10-02T00:27:56+00:00",
     *      "stage_vs":null,"state_condition":"done","sm_ack":1,"lfr_ack":0,"sequence":365,"attempts":0,
     *      "transaction":"NIE5Fm36YSJGOOOn","player_transaction":"mrkXahUbYjfbUgHg",
     *      "server":"rtsps://lv2-prod.immedia-semi.com:443/NIE5Fm36YSJGOOOn","duration":9,
     *      "by_whom":"unknown - 6.1.1 (8854) #e06341d7f - liveview","diagnostic":false,
     *      "debug":"{\"lfr_ok\":[2000001,1,365,205,151,159,167,0]},LV907","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001}],"media_id":null}
     **/
    async startLiveView({accountId, networkId, cameraId}) {
        const data = {
            'intent': 'liveview',
            'motion_event_start_time': '',
        };
        const targetAccount = accountId || this.accountID;
        const path = `/api/v6/accounts/${targetAccount}/networks/${networkId}/cameras/${cameraId}/liveview/`;
        return await this.post(path, data);
    }

    async getCameraLiveViewV5(networkID, cameraID) {
        return await this.startLiveView({accountId: this.accountID, networkId: networkID, cameraId: cameraID});
    }

    /**
     * see: SAMPLE.CAMERA_STATUS
     */
    async updateCameraStatus(networkID, cameraID) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/status`);
    }

    /**
     * POST {"temp_max":88,"id":4000001,"current_temp":73,"temp_min":50,"network":2000001}
     * {"complete":true,"status":0,"status_msg":"Command succeeded","status_code":908,
     *  "commands":[{"id":750081889,"created_at":"2020-10-02T00:27:08+00:00","updated_at":"2020-10-02T00:27:11+00:00",
     *      "execute_time":"2020-10-02T00:27:08+00:00","command":"temp_calibrate","state_stage":"dev",
     *      "stage_rest":"2020-10-02T00:27:08+00:00","stage_cs_db":"2020-10-02T00:27:09+00:00",
     *      "stage_cs_sent":"2020-10-02T00:27:09+00:00","stage_sm":"2020-10-02T00:27:09+00:00",
     *      "stage_dev":"2020-10-02T00:27:11+00:00","stage_is":null,"stage_lv":null,"stage_vs":null,
     *      "state_condition":"done","sm_ack":1,"lfr_ack":0,"sequence":360,"attempts":0,"transaction":"sf61Hj9V8tVDNU",
     *      "player_transaction":"vwL7YY0xf9-d3Vpq","server":null,"duration":73,
     *      "by_whom":"unknown - 6.1.1 (8854) #e06341d7f","diagnostic":false,
     *      "debug":"{\"lfr_ok\":[2000001,1,360,205,147,159,165,0]}","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001
     *   }],
     *   "media_id":null}
     * {"id":750081889,"created_at":"2020-10-02T00:27:08+00:00","updated_at":"2020-10-02T00:27:08+00:00",
     *      "execute_time":"2020-10-02T00:27:08+00:00","command":"temp_calibrate","state_stage":"rest",
     *      "stage_rest":"2020-10-02T00:27:08+00:00","stage_cs_db":null,"stage_cs_sent":null,"stage_sm":null,
     *      "stage_dev":null,"stage_is":null,"stage_lv":null,"stage_vs":null,"state_condition":"new","sm_ack":null,
     *      "lfr_ack":null,"sequence":null,"attempts":0,"transaction":"sf61Hj9V8FstVDNU",
     *      "player_transaction":"vwL7YY0xf9-d3Vpq","server":null,"duration":73,
     *      "by_whom":"unknown - 6.1.1 (8854) #e06341d7f","diagnostic":false,"debug":"","opts_1":0,"target":"camera",
     *      "target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,"firmware_id":null,
     *      "network_id":2000001,"account_id":1000001,"sync_module_id":3000001}
     */
    async updateCameraTemperature(networkID, cameraID, currentTempF, minTempF, maxTempF) {
        // {"temp_max":88,"id":4000001,"current_temp":73,"temp_min":50,"network":2000001}
        const body = {
            'temp_max': maxTempF,
            'id': cameraID,
            'current_temp': currentTempF,
            'temp_min': minTempF,
            'network': networkID,
        };
        return await this.post(`/api/v1/network/${networkID}/camera/${cameraID}/calibrate`, body);
    }

    /**
     * {"video_quality":"standard","record_audio_enable":true,"illuminator_enable":0,"video_length":30,
     *  "early_termination":true,"name":"Alpha","motion_sensitivity":5,"illuminator_intensity":7,"motion_alert":false,
     *  "lfr_sync_interval":8,"alert_interval":10}
     * {"id":750081909,"created_at":"2020-10-02T00:27:14+00:00","updated_at":"2020-10-02T00:27:14+00:00",
     *    "execute_time":"2020-10-02T00:27:14+00:00","command":"config_set","state_stage":"rest",
     *    "stage_rest":"2020-10-02T00:27:14+00:00","stage_cs_db":null,"stage_cs_sent":null,"stage_sm":null,
     *    "stage_dev":null,"stage_is":null,"stage_lv":null,"stage_vs":null,"state_condition":"new","sm_ack":null,
     *    "lfr_ack":null,"sequence":null,"attempts":0,"transaction":"iPYvI_VT4Dovb","player_transaction":"s0OXguCLB74",
     *    "server":null,"duration":null,"by_whom":"unknown - 6.1.1 (8854) #e06341d7f","diagnostic":false,"debug":"",
     *    "opts_1":0,"target":"camera","target_id":4000001,"parent_command_id":null,"camera_id":4000001,"siren_id":null,
     *    "firmware_id":null,"network_id":2000001,"account_id":1000001,"sync_module_id":3000001}
     **/
    async updateCameraSettings(networkID, cameraID, updateCameraBody) {
        return await this.post(`/network/${networkID}/camera/${cameraID}/update`, updateCameraBody);
    }

    async updateCameraMotionRegions(networkID, cameraID, motionRegions) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/cameras/${cameraID}/motion_regions`,
            motionRegions);
    }

    async disableCameraTempAlert(networkID, cameraID) {
        return await this.post(`/api/v1/network/${networkID}/camera/${cameraID}/temp_alert_disable`);
    }

    async enableCameraTempAlert(networkID, cameraID) {
        return await this.post(`/api/v1/network/${networkID}/camera/${cameraID}/temp_alert_enable`);
    }

    /**
     * see: SAMPLE.CAMERA_SIGNALS
     */
    async getCameraSignals(networkID, cameraID) {
        return await this.get(`/network/${networkID}/camera/${cameraID}/signals`);
    }

    /**
     * SIREN
     */

    async getSirens() {
        return await this.get(`/sirens`);
    }

    async getNetworkSirens(networkID) {
        return await this.get(`/api/v1/networks/${networkID}/sirens/`);
    }

    async activateSiren(networkID, sirenID, duration = 30) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/${sirenID}/activate/`, {duration});
    }

    async activateSirens(networkID, duration = 30) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/activate/`, {duration});
    }

    // async createSiren(networkID, addSirenNetworkBody) {
    //     return await this.post(`/api/v1/networks/${networkID}/sirens/add/`, addSirenNetworkBody);
    // }

    async deactivateSirens(networkID) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/deactivate/`);
    }

    // async deleteSirens(networkID, sirenID) {
    //     return await this.post(`/api/v1/networks/${networkID}/sirens/${sirenID}/delete`);
    // }

    async updateSiren(networkID, sirenID, sirenNameBody) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/${sirenID}/update`, sirenNameBody);
    }

    async updateSirens(networkID, sirenDurationBody) {
        return await this.post(`/api/v1/networks/${networkID}/sirens/update`, sirenDurationBody);
    }

    /**
     * CHIME
     */

    async createChime(networkID, addSirenNetworkBody) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/chimes/add/`, addSirenNetworkBody);
    }

    /**
     * OWL
     */

    /**
     * see: SAMPLE.OWL_CONFIG
     */
    async getOwlConfig(networkID, owlID) {
        return await this.get(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/config`);
    }

    async getOwlLiveView(networkID, owlID, liveViewBody) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/liveview`,
            liveViewBody);
    }

    async updateOwlStatus(networkID, owlID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/status`);
    }

    async updateOwlSettings(networkID, owlID, updateOwlBody) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/config`, updateOwlBody);
    }

    async updateOwlThumbnail(networkID, owlID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/thumbnail`);
    }

    // async createOwl(networkID, addOwlBody) {
    //     return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/add`, addOwlBody);
    // }

    async changeOwlWifi(networkID, owlID, onboardingStartRequest) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/change_wifi`,
            onboardingStartRequest);
    }

    // async deleteOwl(networkID, owlID) {
    //     return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/${owlID}/delete`);
    // }

    // async addOwl(networkID, onboardingStartRequest) {
    //    return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/owls/add`, onboardingStartRequest);
    // }

    /**
     * METWORK
     */

    /**
     * see: SAMPLE.NETWORKS
     */
    async getNetworks() {
        return await this.get(`/networks`);
    }

    /**
     * see: SAMPLE.ARM_NETWORK
     */
    async armNetwork(networkID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/state/arm`);
    }

    /**
     * see: SAMPLE.DISARM_NETWORK
     */
    async disarmNetwork(networkID) {
        return await this.post(`/api/v1/accounts/{accountID}/networks/${networkID}/state/disarm`);
    }

    // async createNetwork(addNetworkBody) {
    //     return await this.post(`/network/add`, addNetworkBody);
    // }

    // async deleteNetwork(networkID) {
    //     return await this.post(`/network/${networkID}/delete`);
    // }

    /**
     * POST {"dst":true,"lv_mode":"relay","time_zone":"America\/Toronto"}
     * {"dst":true,"lv_mode":"relay","time_zone":"America\/Toronto"}
     * {"network":{"id":2000001,"created_at":"2016-02-13T19:15:54+00:00","updated_at":"2020-10-02T00:29:30+00:00",
     *   "deleted_at":null,"name":"82 Downing","network_key":"hifSnlicp+k4bLA=","description":"",
     *   "network_origin":"normal","locale":"","time_zone":"America/Toronto","dst":true,"ping_interval":60,
     *   "encryption_key":null,"armed":false,"autoarm_geo_enable":false,"autoarm_time_enable":false,"lv_mode":"relay",
     *   "lfr_channel":0,"video_destination":"server","storage_used":0,"storage_total":0,"video_count":0,
     *   "video_history_count":4000,"sm_backup_enabled":false,"arm_string":"Disarmed","busy":false,"camera_error":false,
     *   "sync_module_error":false,"feature_plan_id":null,"account_id":1000001,"lv_save":false}}
     **/
    async updateNetwork(networkID, updateNetworkSaveAllLiveViews) {
        return await this.post(`/network/${networkID}/update`, updateNetworkSaveAllLiveViews);
    }

    /**
     * see: SAMPLE.DEVICE
     */
    async getDevice(serialNumber) {
        return await this.get(`/api/v1/devices/identify/${serialNumber}`);
    }

    // async addSyncModuleDevice(networkID, type, onboardingStartRequest) {
    //     return await this.post(`/api/v2/network/${networkID}/sync_module/${type}`);
    // }

    // async deleteSyncModule(networkID, syncModuleID) {
    //     return await this.post(`/network/${networkID}/syncmodule/${syncModuleID}/delete/`);
    // }

    async updateSystem(networkID, updateSystemNameBody) {
        return await this.post(`/network/${networkID}/update`, updateSystemNameBody);
    }

    async updateNetworkTimezone(networkID, updateTimezoneBody) {
        return await this.post(`/network/${networkID}/update`, updateTimezoneBody);
    }

    /**
     * BLINK CORE
     */

    /**
     * see: SAMPLE.BLINK_STATUS
     */
    async getBlinkStatus(tier = 'prod') {
        return await this.get(`https://blinkstatus.net/api/v1/${tier}`);
    }

    /**
     * see: SAMPLE.BLINK_SUPPORT
     */
    async getBlinkSupport() {
        return await this.get(`/api/v2/support/ob_phone/`);
    }

    /**
     * see: SAMPLE.BLINK_APP_VERSION
     */
    async getBlinkAppVersion() {
        return await this.get(`/api/v1/version`);
    }

    /**
     * see: SAMPLE.BLINK_REGIONS
     */
    async getBlinkRegions(country = 'US') {
        return await this.get(`/regions?locale=${country}`);
    }

    async getSyncModuleFirmware(serial) {
        return await this.get(`/api/v1/sync_modules/${serial}/fw_update`);
    }

    async getOwlFirmware(serial) {
        return await this.get(`/api/v1/accounts/{accountID}/owls/${serial}/fw_update`);
    }

    async getAppStatus(serial) {
        return await this.get(`/api/v1/fw/app/update_check?serial=${serial}`);
    }
}

module.exports = BlinkAPI;
