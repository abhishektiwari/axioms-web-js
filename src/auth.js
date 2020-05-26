import AuthSession from "./session";
import assign from "lodash/assign";
import defaultsDeep from "lodash/defaultsDeep";
import {
    create_url,
    base64URL
} from "./helper";
import nanoid from "nanoid";
import qs from "qs";
import jws from "jws";
import axios from "axios";
import jwktopem from "jwk-to-pem";
import sha256 from 'crypto-js/sha256';
import cryptoHex from 'crypto-js/enc-hex';
import md5 from 'crypto-js/md5';

class Auth {
    /**
     *  config = {
     *      axioms_domain         : "auth.example.com",
     *      response_type         : "id_token token",
     *      redirect_uri          : "https://app.example.com/callback",
     *      post_logout_uri       : "https://app.example.com/login",
     *      client_id             : "asd_88-hasd99asd",
     *      scope                 : "openid profile",
     *      login_type            : "redirect",
     *      post_login_navigate   : "/",
     *      auto_refresh          : true,
     *      auto_refresh_buffer   : 60000
     * }
     **/

    constructor(config) {
        this.prompt_options = ["none", "login", "consent", "select_account"];
        this.authorization_code = false;
        // For now only Implicit Flow
        this.response_options = ["code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"];
        if (!config) {
            throw new ReferenceError("A cofig must be provided");
        }
        if (!config.axioms_domain) {
            throw new ReferenceError("A axiomDomain must be provided");
        }
        if (config.scope.includes('offline_access')) {
            throw new Error("offline_access is not allowed scope for public clients");
        }
        if (!config.scope.includes('openid')) {
            throw new Error("openid is a required scope");
        }
        if (!config.response_type &&
            !this.response_options.includes(config.response_type.trim())
        ) {
            throw new ReferenceError("A valid response_type must be provided");
        }
        if (config.response_type.trim().includes('code')) {
            this.authorization_code = true;
        }
        if (!config.redirect_uri) {
            throw new ReferenceError("A redirect_uri must be provided");
        }
        if (!config.client_id) {
            throw new ReferenceError("A client_id must be provided");
        }
        if (!config.post_login_navigate) {
            throw new ReferenceError(
                "A path to navigate after post login must be provided"
            );
        }
        this.config = config;
        this.authorize_endpoint = `https://${this.config.axioms_domain}/oauth2/authorize`;
        this.token_endpoint = `https://${this.config.axioms_domain}/oauth2/token`;
        this.jwks_endpoint = `https://${this.config.axioms_domain}/oauth2/.well-known/jwks.json`;
        this.logout_endpoint = `https://${this.config.axioms_domain}/oauth2/logout`;
        this.user_settings_endpoint = `https://${this.config.axioms_domain}/user/settings/profile`;
        this.user_password_endpoint = `https://${this.config.axioms_domain}/user/settings/password`;
        this.claims_prefix = `https://${this.config.axioms_domain}/claims/`;
        this.userinfo_endpoint = `https://${this.config.axioms_domain}/oauth2/userinfo`;
        this.passwordless_email_link_api = `https://${this.config.axioms_domain}/api/passwordless/email/link`;

        this.config = defaultsDeep(config, {
            login_type: "redirect",
            storage_type: "session",
            auto_refresh: true,
            auto_refresh_buffer: 60000,
            jwks_endpoint: this.jwks_endpoint
        });
        this.session = new AuthSession(this.config);
        this.has_id = false;
        this.has_access = false;
    }

    authorize_url(prompt, response_type, scope = null, org_hint = null) {
        this.session.state = nanoid();
        this.session.nonce = nanoid();
        this.session.code_verifier = nanoid();
        this.session.code_challenge = base64URL(sha256(this.session.code_verifier));

        return create_url(
            this.authorize_endpoint,
            assign({
                state: this.session.state,
                nonce: this.session.nonce,
                response_type: response_type ?
                    response_type : this.config.response_type,
                redirect_uri: this.config.redirect_uri,
                client_id: this.config.client_id,
                scope: scope ? scope : this.config.scope,
                prompt: this.prompt_options.includes(prompt) ? prompt : undefined,
                org_hint: org_hint ? org_hint : undefined,
                code_challenge: this.authorization_code ? this.session.code_challenge : undefined,
                code_challenge_method: this.authorization_code ? 'S256' : undefined
            })
        );
    }

    navigate_url(url) {
        location.href = url;
    }

    async login_with_email_link(email) {
        if (!this.config.scope.includes('email')) {
            throw new Error("email is a required scope");
        }
        let response;
        let data;
        this.session.state_cookie = nanoid();
        this.session.nonce_cookie = md5(email).toString();
        data = {
            'email': email,
            response_type: this.config.response_type,
            redirect_uri: this.config.redirect_uri,
            client_id: this.config.client_id,
            scope: this.config.scope,
            state: this.session.state_cookie,
            nonce: this.session.nonce_cookie
        }
        if (this.authorization_code) {
            this.session.code_verifier_cookie = nanoid();
            this.session.code_challenge_cookie = base64URL(sha256(this.session.code_verifier));
            data['code_challenge'] = this.session.code_challenge_cookie;
            data['code_challenge_method'] = 'S256';
        }
        try {
            response = await axios({
                method: 'post',
                url: this.passwordless_email_link_api,
                data: data
            });
            return response.data.msg;
        } catch (error) {
            console.error(error.response.data.msg);
            this.session.clear_all('cookie');
            throw new Error(error.response.data.msg);
        }
    }

    login_with_redirect(
        prompt = null,
        response_type = null,
        scope = null,
        org_hint = null
    ) {
        /* Saving next path for post login redirect */
        let params;
        if (window.location.search) {
            params = qs.parse(window.location.search, {
                ignoreQueryPrefix: true
            });
            if ('next' in params) {
                this.session.next = params['next']
            }
        }
        /* org_hint is uuid for organization */
        if (this.session.org && !org_hint) {
            org_hint = this.session.org;
        }
        if (this.session.error == "login_required") {
            this.session.clear_errors();
            let url = this.authorize_url(prompt, response_type, scope, org_hint);
            this.navigate_url(url);
        } else {
            this.session.clear_errors();
            let url = this.authorize_url("none", response_type, scope, org_hint);
            this.navigate_url(url);
        }
    }

    switch_organization(org_hint) {
        this.login_with_redirect(null, null, null, org_hint);
    }

    new_access_token() {
        let url = this.authorize_url("none", "token");
        return url;
    }

    new_id_token() {
        let url = this.authorize_url("none", "code", "openid profile");
        return url;
    }

    logout_url() {
        this.session.state = nanoid();
        return create_url(
            this.logout_endpoint,
            assign({
                state: this.session.state,
                id_token_hint: this.session.id_token,
                post_logout_redirect_uri: this.config.post_logout_uri
            })
        );
    }

    logout_with_redirect() {
        let logout_url = this.logout_url();
        this.session.clear_all();
        return this.navigate_url(logout_url);
    }

    get_user_settings_url() {
        return this.user_settings_endpoint;
    }

    get_user_password_url() {
        return this.user_password_endpoint;
    }

    process_authorize_response() {
        let params;
        if (window.location.search) {
            params = qs.parse(window.location.search, {
                ignoreQueryPrefix: true
            });
        }
        if (window.location.hash) {
            params = qs.parse(location.hash.replace(/(#!?[^#]+)?#/, "?"), {
                ignoreQueryPrefix: true
            });
        }

        for (const [key, value] of Object.entries(params)) {
            this.session.parse(key, value);
        }
        history.pushState(
            "",
            document.title,
            location.href.replace(location.search, "").replace(location.hash, "")
        );
        this.handle_authorize_response();
    }

    async handle_authorize_response() {
        switch (this.session.error) {
            case "login_required":
                this.login_with_redirect();
                break;
            case "invalid_request":
                console.error(this.session.error, this.session.error_description);
                break;
            case "invalid_client":
                console.error(this.session.error, this.session.error_description);
                break;
            case "unsupported_grant_type":
                console.error(this.session.error, this.session.error_description);
                break;
            case "invalid_grant":
                console.error(this.session.error, this.session.error_description);
                break;
            case "access_denied":
                console.error(this.session.error, this.session.error_description);
                break;
            case "unauthorized_client":
                console.error(this.session.error, this.session.error_description);
                break;
            default:
                if (this.session.state === undefined) {
                    // This means state in authorization response
                    // is different from original
                    throw new Error("Invalid state error");
                }
                try {
                    let keys = await this.get_jwks_keys();
                    if (keys) {
                        this.handle_token_state();
                        if (this.session.code && this.authorization_code) {
                            this.session.clear_errors();
                            try {
                                let code = await this.get_tokens_from_token_endpoint();
                                if (code) {
                                    this.handle_token_endpoint_response();
                                }
                            } catch (error) {
                                console.error(error);
                            }
                        } else {

                            this.handle_post_login_navigate();
                        }
                    }
                } catch (error) {
                    console.error(error)
                }
                break;
        }
    }

    handle_post_login_navigate() {
        var goTo = this.config.post_login_navigate;
        if (this.session.next) {
            goTo = this.session.next;
            this.session.clear_next();
        }
        this.navigate_url(goTo);
    }

    handle_token_state() {
        if (this.session.id_token) {
            this.has_id = true;
            this.is_token_valid('id_token');
        } else {
            this.has_id = false;
        }
        if (this.session.access_token) {
            this.has_access = true;
        } else {
            this.has_access = false;
        }
    }

    handle_token_endpoint_response() {
        if (this.session.error) {
            console.error(this.session.error_description);
        } else {
            this.handle_token_state();
            if (this.session.is_authenticated()) {
                this.handle_post_login_navigate();
            }

        }
    }

    async get_userinfo() {
        let response;
        if (!this.session.access_token) {
            throw new Error("No valid access token in the session");
        }
        try {
            response = await axios.get(this.userinfo_endpoint, {
                headers: {
                    'Authorization': `Bearer ${this.session.access_token}`
                }
            })
            this.session.userinfo = response.data;
            if (this.session.userinfo) {
                var roles = Object.prototype.hasOwnProperty.call(this.session.userinfo, `${this.claims_prefix}roles`) ?
                    this.session.userinfo[`${this.claims_prefix}roles`] :
                    null;
                if (roles) {
                    this.session.roles = roles;
                }
                var orgs = Object.prototype.hasOwnProperty.call(this.session.userinfo, `${this.claims_prefix}orgs`) ?
                    this.session.userinfo[`${this.claims_prefix}orgs`] :
                    null;
                if (orgs) {
                    this.session.orgs = orgs;
                }
                var permissions = Object.prototype.hasOwnProperty.call(this.session.userinfo, `${this.claims_prefix}permissions`) ?
                    this.session.userinfo[`${this.claims_prefix}permissions`] :
                    null;
                if (permissions) {
                    this.session.permissions = permissions;
                }
            }
        } catch (error) {
            throw error;
        }
    }

    async get_tokens_from_token_endpoint() {
        let response;
        try {
            response = await axios({
                method: 'post',
                url: this.token_endpoint,
                data: qs.stringify({
                    'code': this.session.code,
                    'client_id': this.config.client_id,
                    'code_verifier': this.session.code_verifier,
                    'redirect_uri': this.config.redirect_uri,
                    'grant_type': 'authorization_code'
                }),
                headers: {
                    'content-type': 'application/x-www-form-urlencoded;charset=utf-8'
                }
            })
            for (const [key, value] of Object.entries(response.data)) {
                this.session.parse(key, value);
            }
        } catch (error) {
            throw error;
        }
        return response.data;
    }

    async get_jwks_keys() {
        let response;
        let keys;
        try {
            response = await axios.get(this.jwks_endpoint);
            keys = response.data.keys;
            if (!keys || !keys.length) {
                console.error("No public keys found");
                this.session.is_valid_id_token = false;
            } else {
                this.session.keys = keys;
            }
        } catch (error) {
            throw error;
        }
        return keys;
    }

    is_token_valid(type) {
        let unverified_token = this.get_unverified_token(type);
        try {
            let key = this.session.keys.find(
                key => key.kty === "RSA" && key.kid == unverified_token.kid
            );
            if (key) {
                if (type === 'id_token') {
                    this.verify_id_token(key, unverified_token.alg, unverified_token.payload);
                }
            } else {
                throw "No matching key found";
            }
        } catch (error) {
            console.error(error);
            if (type === 'id_token') {
                this.session.is_valid_id_token = false;
            }
        }
    }

    get_unverified_token(type) {
        let token = this.session[type];
        let decoded = jws.decode(token);
        let alg = decoded.header.alg;
        let kid = decoded.header.kid;
        let payload = decoded.payload;
        let json_token = {
            alg: alg,
            kid: kid,
            payload: JSON.parse(payload)
        };
        return json_token;
    }

    verify_id_token(key, alg, payload) {
        let token = this.session.id_token;
        this.session.is_valid_id_token = jws.verify(token, alg, jwktopem(key));
        this.session.id_payload = payload;
        this.session.id_exp = payload.exp;
        this.session.org = Object.prototype.hasOwnProperty.call(payload, "org") ?
            payload.org :
            null;
        this.session.roles = Object.prototype.hasOwnProperty.call(payload, `${this.claims_prefix}roles`) ?
            payload[`${this.claims_prefix}roles`] :
            null;
        this.session.orgs = Object.prototype.hasOwnProperty.call(payload, `${this.claims_prefix}orgs`) ?
            payload[`${this.claims_prefix}orgs`] :
            null;
        this.session.permissions = Object.prototype.hasOwnProperty.call(payload, `${this.claims_prefix}permissions`) ?
            payload[`${this.claims_prefix}permissions`] :
            null;
        this.session.org_uri = Object.prototype.hasOwnProperty.call(payload, "uri") ?
            payload.uri :
            null;
        this.session.id_scope = Object.prototype.hasOwnProperty.call(
                payload,
                "scope"
            ) ?
            payload.scope :
            null;
        var at_hash = Object.prototype.hasOwnProperty.call(
                payload,
                "at_hash"
            ) ?
            payload.at_hash :
            false;
        var c_hash = Object.prototype.hasOwnProperty.call(
                payload,
                "c_hash"
            ) ?
            payload.c_hash :
            false;
        var s_hash = Object.prototype.hasOwnProperty.call(
                payload,
                "s_hash"
            ) ?
            payload.s_hash :
            false;
        // Ensure nonce in id token is same as before authorization request was made
        // Ensure state in response is same as before authorization request was made
        var nonce = this.session.nonce;
        if (!nonce) {
            nonce = this.session.nonce_cookie;
            if (!nonce) {
                this.session.is_valid_id_token = false;
            } else {
                /* This is passwordless flow using email link */
                if (md5(payload.email).toString() !== nonce) {
                    this.session.is_valid_id_token = false;
                }
            }
        }
        if (this.config.response_type.includes('id_token') && (payload.nonce !== nonce)) {
            this.session.is_valid_id_token = false;
        }
        // Check at_hash, c_hash, and s_hash
        // If not matched set is_valid_id_token to false
        if (at_hash) {
            console.log('at_hash');
            if (!this.get_hash_left_half(this.session.access_token, at_hash)) {
                this.session.is_valid_id_token = false;
            }
        }
        if (c_hash) {
            console.log('c_hash');
            if (!this.get_hash_left_half(this.session.code, c_hash)) {
                this.session.is_valid_id_token = false;
            }
        }
        if (s_hash) {
            console.log('s_hash');
            if (!this.get_hash_left_half(this.session.state, s_hash)) {
                this.session.is_valid_id_token = false;
            }
        }

        // Clear all cookies
        this.session.clear_all('cookie');
    }

    get_hash_left_half(bString, vString) {
        var digest = cryptoHex.stringify(sha256(bString));
        var half_length = Math.ceil(digest.length / 2);
        var left_most = base64URL(cryptoHex.parse(digest.substring(0, half_length)));
        if (left_most === vString) {
            return true
        } else {
            return false
        }

    }
}

export {
    Auth
};
export default Auth;