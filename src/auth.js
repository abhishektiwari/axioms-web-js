import AuthSession from "./session";
import assign from "lodash/assign";
import defaultsDeep from "lodash/defaultsDeep";
import { create_url } from "./helper";
import nanoid from "nanoid";
import qs from "qs";
import jws from "jws";
import axios from "axios";
import jwktopem from "jwk-to-pem";

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
        // For now only Implicit Flow
        this.response_options = ["id_token", "token id_token", "id_token token"];
        if (!config) {
            throw new ReferenceError("A cofig must be provided");
        }
        if (!config.axioms_domain) {
            throw new ReferenceError("A axiomDomain must be provided");
        }
        if (!config.response_type &&
            !this.response_options.includes(config.response_type)
        ) {
            throw new ReferenceError("A valid response_type must be provided");
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
        this.jwks_endpoint = `https://${this.config.axioms_domain}/oauth2/.well-known/jwks.json`;
        this.logout_endpoint = `https://${this.config.axioms_domain}/oauth2/logout`;
        this.user_settings_endpoint = `https://${this.config.axioms_domain}/user/settings/profile`;
        this.user_password_endpoint = `https://${this.config.axioms_domain}/user/settings/password`;

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
                org_hint: org_hint ? org_hint : undefined
            })
        );
    }

    navigate_url(url) {
        location.href = url;
    }

    login_with_redirect(
        prompt = null,
        response_type = null,
        scope = null,
        org_hint = null
    ) {
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

    switch_organization(org) {
        this.login_with_redirect(null, null, null, org);
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
        switch (this.session.error) {
            case "login_required":
                this.login_with_redirect();
                break;
            case "invalid_request":
                console.error(this.session.error_description);
                break;
            default:
                if (this.session.id_token && this.session.access_token) {
                    this.has_id = true;
                    this.has_access = true;
                    this.check_token_validity();
                } else if (this.session.id_token) {
                    this.has_id = true;
                    this.has_access = false;
                    this.check_token_validity();
                } else {
                    this.session.is_valid_id_token = false;
                }
                break;
        }
    }

    check_token_validity() {
        let id_token = null;
        let access_token = null;
        let options = {
            json: true,
            uri: this.jwks_endpoint,
            strictSsl: true
        };
        if (this.has_id) {
            id_token = this.pre_process_token("id_token");
        }
        if (this.has_access) {
            access_token = this.pre_process_token("access_token");
        }
        axios.get(this.jwks_endpoint)
            .then(response => {
                var keys = response.data.keys;
                console.log(response.data);
                if (!keys || !keys.length) {
                    console.error("No public keys to verify id_token");
                    this.session.is_valid_id_token = false;
                } else {
                    if (id_token) {
                        let key = keys.find(
                            key => key.kty === "RSA" && key.kid == id_token.kid
                        );
                        this.post_process_id_token(key, id_token.alg, id_token.payload);
                    } else {
                        this.session.is_valid_id_token = false;
                    }
                    if (this.has_access) {
                        let key = keys.find(
                            key => key.kty === "RSA" && key.kid == access_token.kid
                        );
                        this.post_process_access_token(
                            key,
                            access_token.alg,
                            access_token.payload
                        );
                    } else {
                        this.session.is_valid_access_token = false;
                    }
                    this.navigate_url(this.config.post_login_navigate);
                }
            })
            .catch(function(err) {
                console.error(err);
                this.session.is_valid_id_token = false;
                this.session.is_valid_access_token = false;
            });
    }

    pre_process_token(type) {
        let token = this.session[type];
        let decoded = jws.decode(token);
        let alg = decoded.header.alg;
        let kid = decoded.header.kid;
        let payload = decoded.payload;
        let res = {
            alg: alg,
            kid: kid,
            payload: JSON.parse(payload)
        };
        return res;
    }

    post_process_access_token(key, alg, payload) {
        let token = this.session.id_token;
        this.session.is_valid_access_token = jws.verify(token, alg, jwktopem(key));
        this.session.access_payload = payload;
        this.session.access_exp = payload.exp;
        this.session.access_scope = Object.prototype.hasOwnProperty.call(
                payload,
                "scope"
            ) ?
            payload.scope :
            null;
    }

    post_process_id_token(key, alg, payload) {
        let token = this.session.access_token;
        this.session.is_valid_id_token = jws.verify(token, alg, jwktopem(key));
        this.session.id_payload = payload;
        this.session.id_exp = payload.exp;
        this.session.org = Object.prototype.hasOwnProperty.call(payload, "org") ?
            payload.org :
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
        // Ensure nonce in id token is same as before authorization request was made
        // Ensure state in reponse is same as before authorization request was made
        if (
            payload.nonce !== this.session.nonce ||
            this.session.state === undefined
        ) {
            this.session.is_valid_id_token = false;
        }
    }
}

export { Auth };
export default Auth;