# web-js
Axioms Javascript client for web applications including Single Page Applications such as Vue, Angular, and React.


# Install
Install `web-js` to your web app.

```
npm i @axioms/web-js
```

# Basic configuration

## Vue
In `main.js` add following,

```
import { Auth } from '@axioms/web-js';
const auth = new Auth({
    axioms_domain: 'slug.axioms.io',
    response_type: 'id_token token',
    redirect_uri: 'https://mydomain.com/callback',
    post_logout_uri: 'https://mydomain.com/login',
    client_id: 'yourclientid',
    scope: 'openid profile'
});

Vue.prototype.$auth = auth;
```

In `*.vue` files access access various functions. 

For instance to login,

```
this.$auth.login_with_redirect();
```

For logout,

```
this.$auth.logoutWithRedirect();
```

## Angular

`Coming soon`

## React

`Coming soon`

# Documentation

`Coming soon`