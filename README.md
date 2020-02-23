# web-js ![NPM](https://img.shields.io/npm/v/@axioms/web-js?style=flat-square)
[Axioms](https://axioms.io) Javascript client for web applications including Single Page Applications (SPAs) such as Vue, Angular, and React.

## Prerequisite
1. Create an account with [Axioms](https://axioms.io). Login to your account and create your first `Tenent`. A `Tenent` in Axioms is an isolated container for all your identity and access management data. A `Tenant` holds OAuth2/OpenID configurations, clients, and resources.
2. Create your first `Client`. As this library is designed for SPAs, make sure you have selected `Client Type` as `Single Page Application`. After creating the client, update your client settings with `Callback redirect URL` and `Signout redirect url`. We will use these in our configuration below.
3. Grab the client key which will be used to configure your app.

# Install
Install `web-js` to your web app.

```
npm i @axioms/web-js
```

# Basic usage
Create Axioms `auth` object,

```
import { Auth } from '@axioms/web-js';
const $auth = new Auth({
    axioms_domain: '<placeholder>',
    response_type: 'id_token token',
    redirect_uri: '<placeholder>',
    post_logout_uri: '<placeholder>',
    client_id: '<placeholder>',
    scope: 'openid profile',
    post_login_navigate: '<placeholder>'
});
```

# Standard functions and variables

| Function/Object | Decscription | Examples |
|-------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `$auth.login_with_redirect()` | Login user with redirect to Axioms hosted login page |  |
| `$auth.logoutWithRedirect()` | Logout user with redirect to Axioms hosted login page |  |
| `$auth.session.is_authenticated()` | Check if user session is authenticated or not |  |
| `$auth.get_user_password_url()` | Get user password reset URL if the tenant allows <br>username-password login. |  |
| `$auth.get_user_settings_url()` | Get user settings URL where user can update profile <br>and multi-factor settings. |  |
| `$auth.session.id_payload` | Get payload of ID Token and access individual attributes<br> by name | `$auth.session.id_payload.given_name`,<br>`$auth.session.id_payload.family_name`,<br>`$auth.session.id_payload.picture` |
| `$auth.session.hasAccessScopeScope(required_scopes)` | Check if scope included in ID token matches with required <br>permissions. `required_scopes` must be an array <br>of strings representing the scopes assigned to resources | `['profile', 'openid']`,<br>`['profile', 'openid', 'tenant:owner']` |
| `$auth.session.hasIdScope(required_scopes)` | Check if scope included in access token matches with required <br>permissions. `required_scopes` must be an array <br>of strings representing the scopes assigned to resources | `['profile', 'openid']`,<br>`['profile', 'openid', 'picture']` |
|  |  |  |
## Vue-specific usage
For Vue specific usage please review [sample-vuejs](https://github.com/axioms-io/sample-vuejs)

## React

For React specific usage please review [sample-react](https://github.com/axioms-io/sample-react)

## Angular

`Coming soon`

# Documentation

`Coming soon`