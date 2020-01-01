# web-js
Axioms Javascript client for web applications including Single Page Applications (SPAs) such as Vue, Angular, and React.


# Install
Install `web-js` to your web app.

```
npm i @axioms/web-js
```

# Basic configuration

## Vue

1. Create an account with [Axioms](https://axioms.io). Login to your account and create your first `Tenent`. A `Tenent` in Axioms is an isolated container for all your identity and access management data. A `Tenant` holds OAuth2/OpenID configurations, clients, and resources.
2. Create your first `Client`. As this library is designed for SPAs, make sure you have selected `Client Type` as `Single Page Application`. After creating the client, update your client settings with Callback redirect URLs and Signout redirect urls. We will use these in our configuration below.
3. Grab the client key. Now, in your Vue `main.js` file add create Axioms configuration which looks like below. In following snippet make sure you have replaced placeholder values (anything `<placeholder>`).

```
import { Auth } from '@axioms/web-js';
const auth = new Auth({
    axioms_domain: '<placeholder>',
    response_type: 'id_token token',
    redirect_uri: '<placeholder>',
    post_logout_uri: '<placeholder>',
    client_id: '<placeholder>',
    scope: 'openid profile',
    post_login_navigate: '<placeholder>'
});

Vue.prototype.$auth = auth;
```

In your `*.vue` files access access various `web-js` JavaScript functions via `this`. For instance, 

- To login with redirect,

```
this.$auth.login_with_redirect();
```

- For logout with redirect,

```
this.$auth.logoutWithRedirect();
```

In your `*.js` files you can access various `web-js` JavaScript functions via `Vue.prototype`. For instace,

```
Vue.prototype.$auth.session.is_authenticated()
```

## Angular

`Coming soon`

## React

`Coming soon`

# Documentation

`Coming soon`