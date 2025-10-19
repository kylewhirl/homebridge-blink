const {describe, test, expect, beforeEach, afterEach} = require('@jest/globals');

const mockFetch = jest.fn();
jest.mock('@adobe/fetch', () => ({
    fetch: (...args) => mockFetch(...args),
    reset: jest.fn(),
    __mock: mockFetch,
}));
const fetchMock = mockFetch;

const createResponse = ({status = 200, headers = {}, body = {}} = {}) => {
    const headerMap = new Map();
    const headerEntries = Object.entries(headers);
    if (!headerEntries.some(([key]) => key.toLowerCase() === 'content-type')) {
        headerMap.set('content-type', typeof body === 'string' ? 'text/plain' : 'application/json');
    }
    for (const [key, value] of headerEntries) {
        headerMap.set(key.toLowerCase(), value);
    }
    return {
        status,
        statusText: status === 200 ? 'OK' : 'ERROR',
        ok: status >= 200 && status < 300,
        headers: {
            get: name => headerMap.get(name.toLowerCase()) ?? null,
            set: (name, value) => headerMap.set(name.toLowerCase(), value),
            entries: () => Array.from(headerMap.entries()),
        },
        json: async () => body,
        text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
        arrayBuffer: async () => Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)).buffer,
        _body: undefined,
    };
};

describe('BlinkAPI OAuth and legacy flows', () => {
    let BlinkAPI;
    let IniFile;

    beforeEach(() => {
        jest.clearAllMocks();
        fetchMock.mockReset();
        BlinkAPI = require('./blink-api');
        IniFile = require('./inifile');
        jest.spyOn(IniFile, 'write').mockImplementation(() => {});
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('oauthRefresh_success_rotatesToken', async () => {
        const now = Date.now();
        fetchMock.mockImplementation(url => {
            if (/oauth\/token/.test(url)) {
                return Promise.resolve(createResponse({
                    body: {access_token: 'X', refresh_token: 'B', expires_in: 10},
                }));
            }
            if (/\/api\/v6\/homescreen/.test(url)) {
                return Promise.resolve(createResponse({
                    body: {
                        account: {account_id: 101, client_id: 202, tier: 'u001'},
                        region: {rest: 'https://rest-u001.immedia-semi.com'},
                    },
                }));
            }
            if (/\/api\/v6\/test/.test(url)) {
                return Promise.resolve(createResponse({body: {ok: true}}));
            }
            throw new Error(`Unhandled fetch: ${url}`);
        });

        const api = new BlinkAPI('uuid', {path: '/tmp/mock.ini', section: 'default', oauth: {refreshToken: 'A'}});
        api.tokenStore.accessTokenExpiresAt = now - 1000;

        await api.ensureSession();
        await api.get('/api/v6/test', 0);

        const testCall = fetchMock.mock.calls.find(([url]) => /\/api\/v6\/test/.test(url));
        expect(testCall).toBeDefined();
        expect(testCall[1].headers.Authorization).toBe('Bearer X');
        expect(api.tokenStore.refreshToken).toBe('B');
        expect(IniFile.write).toHaveBeenCalledWith(expect.any(String), expect.any(String), expect.objectContaining({
            refresh_token: 'B',
            access_token: 'X',
        }));
    });

    test('request_401_triggers_refresh_once', async () => {
        let dataCall = 0;
        fetchMock.mockImplementation(url => {
            if (/\/api\/v6\/data/.test(url)) {
                dataCall += 1;
                if (dataCall === 1) {
                    return Promise.resolve(createResponse({status: 401, body: {message: 'expired'}}));
                }
                return Promise.resolve(createResponse({body: {result: 'ok'}}));
            }
            if (/oauth\/token/.test(url)) {
                return Promise.resolve(createResponse({
                    body: {access_token: 'Y', refresh_token: 'Y2', expires_in: 100},
                }));
            }
            if (/\/api\/v6\/homescreen/.test(url)) {
                return Promise.resolve(createResponse({
                    body: {account: {account_id: 300, client_id: 400, tier: 'prod'}},
                }));
            }
            throw new Error(`Unhandled fetch: ${url}`);
        });

        const api = new BlinkAPI('uuid', {
            oauth: {refreshToken: 'refresh-token'},
            accessToken: 'old',
            accessTokenExpiresAt: Date.now() + 600000,
        });

        const response = await api.get('/api/v6/data', 0);

        expect(response).toEqual({result: 'ok'});
        const oauthCalls = fetchMock.mock.calls.filter(([url]) => /oauth\/token/.test(url));
        expect(oauthCalls).toHaveLength(1);
        const retryHeaders = fetchMock.mock.calls[3][1].headers;
        expect(retryHeaders.Authorization).toBe('Bearer Y');
    });

    test('legacyLogin_426_throws', async () => {
        fetchMock.mockImplementation(url => {
            if (/account\/login/.test(url)) {
                return Promise.resolve(createResponse({
                    status: 426,
                    body: {message: 'Upgrade Required'},
                }));
            }
            throw new Error(`Unhandled fetch: ${url}`);
        });

        const api = new BlinkAPI('uuid', {
            enableLegacyLogin: true,
            preferOAuth: false,
            email: 'user@example.com',
            password: 'secret',
        });

        await expect(api.loginLegacy()).rejects.toThrow(/Upgrade Required/);
    });

    test('liveview_post_works', async () => {
        fetchMock.mockImplementation(url => {
            if (/liveview\//.test(url)) {
                return Promise.resolve(createResponse({
                    body: {
                        server: 'immis://example',
                        liveview_token: 'token123',
                        command_id: 42,
                    },
                }));
            }
            throw new Error(`Unhandled fetch: ${url}`);
        });

        const api = new BlinkAPI('uuid', {
            oauth: {refreshToken: 'refresh'},
            accessToken: 'access',
            accessTokenExpiresAt: Date.now() + 600000,
        });
        api.accountID = 321;
        api.region = 'u003';

        const payload = await api.startLiveView({accountId: 321, networkId: 654, cameraId: 987});

        expect(payload.server).toBe('immis://example');
        expect(payload.liveview_token).toBe('token123');
        const [url, options] = fetchMock.mock.calls[0];
        expect(url).toBe('https://rest-u003.immedia-semi.com/api/v6/accounts/321/networks/654/cameras/987/liveview/');
        expect(options.headers.Authorization).toBe('Bearer access');
    });
});
