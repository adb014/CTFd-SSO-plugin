# CTFd-SSO-plugin

This plugin allows login and registration via OAuth2.

Works perfectly with a large variety of identity management solutions, like KeyCloak.

![](screenshots/login.png)

## Installation

1. Clone this repository to [CTFd/plugins](https://github.com/CTFd/CTFd/tree/master/CTFd/plugins).
2. Install required python packages. If you are using Docker, it is done by rebuilding the container. Instead, if you are using other hosting solutions, you can install them with the command `pip3 install -r requirements.txt` from the plugin folder (`CTFd/plugins/CTFd-SSO-plugin`).
3. Edit the `[extra]` section of `CTFd/config.ini` adding these two values:
   - `OAUTH_HAS_ROLES`: set `True` if you want to allow automatic registration of administrators via OAuth. This relies on the API Endpoint returning the `roles` key. Default is `False`.
   - `OAUTH_ALLOWED_ADMIN_ROLES`: a comma separated list of roles that will be treated as administrators 
   - `OAUTH_CREATE_BUTTONS`: set `True` if you want to automatically add the OAuth login buttons in the login page. Default is `False`.
   - `OAUTH_NO_LOCAL_USERS`: set `True` if you only want to allow OAuth logins
   - `OAUTH_SSO_LOGOUT`: set `True` if you wish for a logout from CTFd to force the logout from the OAuth provider. This requires that the provider supplies a `end_session_endpoint` in its server metadata.
4. Start or restart CTFd.
5. In the `Admin Panel` go to `Plugins`>`ctfd-sso`. There you can view and delete existing clients, or add a new one by pressing plus symbol.
6. Insert a client name (it will be shown on the button) and the other information according to the identity provider. Then press `Add`.
7. Log in :)

## Automatic account creation

If CTFd is configured to allow account creation, the user of OAuth for a missing account will create the account. The test for an existing account is based on the email address returned from the OAuth provider.

The user is created based on the `id_token` returned from the OAuth server if `OAUTH_HAS_ROLES` is not set. Otherwise, as discussed below the user is created based on the `roles` key returned by the API Endpoint.

## Admin accounts

If you want to automatically create admin accounts via the Identity Provider, make sure that the API Endpoint returns a key `roles` containing an array.

For example if an user should be admin, the Identity Provider should return something like: `{"preferred_username": "username", "email": "example@ctfd.org", "roles": ["admin"]}`

The allowed administrator roles for CTFd are determined by the list `OAUTH_ALLOWED_ADLIN_ROLES`, if a user has a role in this list they will be treated as an administrator. This behavior is only possible with the `OAUTH_HAS_ROLES` configuration set. In this other case the administration role must be assigned to the user form the CTFd administration console.

## Login buttons

If configured properly, this plugin will attempt to automatically insert the login buttons in the login page. It might fail if the theme isn't the original one. In this case or if you want to create some custom buttons, they should point to `sso/login/<client_id>`.

## Screenshots

![](screenshots/list.png 'Clients list')
![](screenshots/add.png 'Add client')
