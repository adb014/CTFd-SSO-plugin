""" Plugin entry-point """

import json
import os
import re

from authlib.integrations.flask_client import OAuth

from CTFd.config import process_boolean_str
from CTFd.plugins import override_template
from CTFd.utils import get_app_config

from .blueprint import load_bp
from .models import OAuthClients

PLUGIN_PATH = os.path.dirname(__file__)
CONFIG = json.load(open("{}/config.json".format(PLUGIN_PATH)))


def oauth_clients():
    return OAuthClients.query.all()


def update_login_template(app):
    """
    Gets the actual login template and injects 
    the SSO buttons before the Forms.auth.LoginForm block
    """

    environment = app.jinja_environment
    original = app.jinja_loader.get_source(environment, 'login.html')[0]

    match = re.search(".*Forms\.auth\.LoginForm.*\n", original)

    # If Forms.auth.LoginForm is not found (maybe in a custom template), it does nothing
    if match:
        pos = match.start()

        PLUGIN_PATH = os.path.dirname(__file__)
        if process_boolean_str(get_app_config("OAUTH_NO_LOCAL_USERS")):
            injecting_file_path = os.path.join(
                PLUGIN_PATH, 'templates/login_oauth_no_local.html')
        else:
             injecting_file_path = os.path.join(
                PLUGIN_PATH, 'templates/login_oauth.html')
        with open(injecting_file_path, 'r') as f:
            injecting = f.read()

        if process_boolean_str(get_app_config("OAUTH_NO_LOCAL_USERS")):
            match2 = re.search("{%\s*endwith\s*%}", original)
            pos2 = match2.end()
            new_template = original[:pos] + injecting + original[pos2:]
        else:
            new_template = original[:pos] + injecting + original[pos:]
        override_template('login.html', new_template)


def update_challenge_template(app):
    # This injection is needed so that clicking on the challenge buttons 
    # after the refresh_token has expired will force an SSO login attempt.
    # It would be better if a failure of the fetch on "/api/v1/challenges/<id>" 
    # forced the SSO login, but difficult to do from a plugin
    environment = app.jinja_environment
    original = app.jinja_loader.get_source(environment, 'challenges.html')[0]
    match = re.search('{% block scripts %}', original)
    if match:
        pos = match.start()
        injecting_file_path = os.path.join(PLUGIN_PATH, 'templates/challenges_sso.html')
        with open(injecting_file_path, 'r') as f:
            injecting = f.read()
        original = original[:pos+19] + injecting + original[pos+19:]

    override_template('challenges.html', original)


def numactive(clients):
  n = 0
  for client in clients:
      if client.enabled:
          n += 1
  return n

def load(app):
    # Create database tables
    app.db.create_all()

    # Get all saved clients and register them
    clients = oauth_clients()
    oauth = OAuth(app)
    for client in clients:
        client.register(oauth)

    # Register oauth_clients() as template global
    app.jinja_env.globals.update(oauth_clients=oauth_clients)

    # Update the login template
    if process_boolean_str(get_app_config("OAUTH_CREATE_BUTTONS")) or \
       process_boolean_str(get_app_config("OAUTH_NO_LOCAL_USERS")):
        update_login_template(app)
        update_challenge_template(app)

    # Register the blueprint containing the routes
    bp = load_bp(oauth)
    app.register_blueprint(bp)

    # Add a function to Jinja2 to count our active Oauth providers
    app.jinja_env.globals.update(numactive=numactive)

    if process_boolean_str(get_app_config("OAUTH_SSO_LOGOUT")):
        # Overwrite existing logout function to treat SSO logout
        app.view_functions["auth.logout"] = app.view_functions["sso.sso_logout"]
