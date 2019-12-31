import AuthSession from './session';
import assign from 'lodash/assign';
import defaultsDeep from 'lodash/defaultsDeep';
import { create_url } from './helper';
import nanoid from 'nanoid';
import qs from 'qs';
import jws from 'jws';
import { fetch_jwkset } from './helper';
import jwktopem from 'jwk-to-pem';

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
     *      storage_type          : "session",
     *      auto_refresh          : true,
     *      auto_refresh_buffer   : 60000
     * }
     **/

    constructor(config) {
        this.prompt_options = ['none', 'login', 'consent', 'select_account']
            // For now only Implicit Flow
        this.response_options = ['id_token', 'token id_toke', 'id_toke token']
        if (!config) {
            throw new ReferenceError('A cofig must be provided')
        }
        if (!config.axioms_domain) {
            throw new ReferenceError('A axiomDomain must be provided')
        }
        if (!config.response_type && !this.response_options.includes(config.response_type)) {
            throw new ReferenceError('A valid response_type must be provided')
        }
        if (!config.redirect_uri) {
            throw new ReferenceError('A redirect_uri must be provided')
        }
        if (!config.client_id) {
            throw new ReferenceError('A client_id must be provided')
        }
        this.config = config;
        this.authorize_endpoint = `https://${this.config.axioms_domain}/oauth2/authorize`;
        this.jwks_endpoint = `https://${this.config.axioms_domain}/oauth2/.well-known/jwks.json`;
        this.logout_endpoint = `https://${this.config.axioms_domain}/oauth2/logout`;

        this.config = defaultsDeep(config, {
            login_type: 'redirect',
            storage_type: 'session',
            auto_refresh: true,
            auto_refresh_buffer: 60000,
            jwks_endpoint: this.jwks_endpoint
        });
        this.session = new AuthSession(this.config);
    }

    authorize_url(prompt, response_type, scope = null, org_hint = null) {
        this.session.state = nanoid();
        this.session.nonce = nanoid();

        return create_url(this.authorize_endpoint, assign({
            'state': this.session.state,
            'nonce': this.session.nonce,
            'response_type': response_type ? response_type : this.config.response_type,
            'redirect_uri': this.config.redirect_uri,
            'client_id': this.config.client_id,
            'scope': scope ? scope : this.config.scope,
            'prompt': this.prompt_options.includes(prompt) ? prompt : undefined,
            'org_hint': org_hint ? org_hint : undefined
        }));
    }

    navigate_url(url) {
        location.href = url;
    }

    login_with_redirect(prompt = null, response_type = null, scope = null, org_hint = null) {
        if (this.session.error == 'login_required') {
            this.session.clear_errors();
            let url = this.authorize_url(prompt, response_type, scope, org_hint);
            this.navigate_url(url);
        } else {
            this.session.clear_errors();
            let url = this.authorize_url('none', response_type, scope, org_hint);
            this.navigate_url(url);
        }
    }

    switch_organization(org) {
        this.login_with_redirect(null, null, null, org);
    }

    new_access_token() {
        let url = this.authorize_url('none', 'token');
        return url;
    }

    new_id_token() {
        let url = this.authorize_url('none', 'code', 'openid profile');
        return url;
    }

    logout_url() {
        this.session.state = nanoid();
        return create_url(this.logout_endpoint, assign({
            'state': this.session.state,
            'id_token_hint': this.session.id_token,
            'post_logout_redirect_uri': this.config.post_logout_uri
        }));
    }

    logout() {
        let logout_url = this.logout_url()
        this.session.clear_all()
        return this.navigate_url(logout_url)
    }

    process_authorize_response() {
        let params
        if (window.location.search) {
            params = qs.parse(window.location.search, { ignoreQueryPrefix: true });
        }
        if (window.location.hash) {
            params = qs.parse(location.hash.replace(/(#!?[^#]+)?#/, '?'), { ignoreQueryPrefix: true });
        }
        for (const [key, value] of Object.entries(params)) {
            this.session.parse(key, value)
        }
        history.pushState('', document.title, location.href.replace(location.search, '').replace(location.hash, ''));
        switch (this.session.error) {
            case 'login_required':
                this.login_with_redirect();
                break;
            case 'invalid_request':
                console.error(this.session.error_description)
                break;
            default:
                if (this.session.id_token) {
                    this.check_id_token_validity();
                } else {
                    this.session.is_valid_id_token = false;
                }
                break;
        }
    }

    check_id_token_validity() {
        try {
            let token = this.session.id_token
            let decoded = jws.decode(this.session.id_token);
            let algorithm = decoded.header.alg;
            let key_id = decoded.header.kid;
            let payload = JSON.parse(decoded.payload);
            let options = {
                json: true,
                uri: this.jwks_endpoint,
                strictSsl: true
            }


            fetch_jwkset(options).then((keys) => {
                if (!keys || !keys.length) {
                    console.error('No public keys to verify id_token')
                    this.is_valid_id_token = false
                } else {
                    let key = keys.find(key => key.kty === 'RSA' && key.kid == key_id)
                    this.session.is_valid_id_token = jws.verify(token, algorithm, jwktopem(key));
                    this.session.id_payload = payload;
                    this.session.id_exp = payload.exp;
                    this.session.org = payload.hasOwnProperty("org") ? payload.org : null;
                    this.session.org_uri = payload.hasOwnProperty("uri") ? payload.uri : null;
                    if (payload.nonce == this.session.nonce && this.session.state !== undefined) {
                        this.navigate_url('/');
                    } else {
                        this.session.is_valid_id_token = false
                    }
                }
            }).catch(function(err) {
                console.error(err)
                this.session.is_valid_id_token = false
            });

        } catch (error) {
            console.error(error);
            this.session.is_valid_id_token = false
        }
    }
}

export { Auth };
export default Auth;