from flask import Blueprint, redirect, render_template, request, url_for
from wtforms import StringField, BooleanField
from wtforms.validators import InputRequired, Optional

from CTFd.cache import clear_user_session
from CTFd.config import process_boolean_str
from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.models import Users, db
from CTFd.utils import get_app_config
from CTFd.utils import user as current_user
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.decorators import admins_only
from CTFd.utils.helpers import error_for
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user

from .models import OAuthClients

import json
import sys
import time
import urllib

plugin_bp = Blueprint('sso', __name__, template_folder='templates', static_folder='static', static_url_path='/static/sso')


class OAuthForm(BaseForm):
    name = StringField("Client name", validators=[InputRequired()])
    client_id = StringField("OAuth client id", validators=[InputRequired()])
    client_secret = StringField("OAuth client secret", validators=[InputRequired()])
    access_token_url = StringField("Access token url", validators=[Optional()])
    authorize_url = StringField("Authorization url", validators=[Optional()])
    api_base_url = StringField("User info url", validators=[Optional()])
    server_metadata_url = StringField("Server metadata url", validators=[Optional()])
    color = StringField("Button Color", validators=[InputRequired()])
    enabled = BooleanField("Enabled")
    submit = SubmitField("Add")

def load_bp(oauth):

    @plugin_bp.after_app_request
    def refresh_token(response):
        # We are not using introspection to validate the tokens
        # but we still want to refresh the token, so that the
        # user isn't logged out of the OAuth provider, even though
        # CTFd is used. This is also used to impose the OAuth
        # providers idle time policy

        # If on login page don't refresh the token. Avoid infinite loop
        if request.path.endswith("/login"):
            return response

        token = request.cookies.get("token")
        if not token:
            return response

        token = json.loads(token.replace("'", '"'))
        refresh_token = token["refresh_token"]
        if not refresh_token:
            return response

        # If expiry of the access_token is longer then 60 seconds
        # away, don't refresh. The refresh_token will expire
        # afterwards in any case
        if time.time() < token["expires_at"] - 60:
            return response

        # As I've stored the token in a cookie, I can't use
        # the on_update_token signal of authlib. Create and
        # parse the request myself
        client_id = request.cookies.get("sso_client_id")
        if client_id:
            client_id = int(client_id)
        else:
            client_id = 1
        client = oauth.create_client(client_id)
        body = urllib.parse.urlencode(
            {
                "refresh_token": refresh_token,
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "grant_type": "refresh_token",
                "scope": token["scope"],
            }
        )
        try:
            data = client.request("POST", client.access_token_url, token, body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"})

            new_token = data.json()["access_token"]
            if new_token:
                response.set_cookie("token", str(new_token), path = path, httponly = True, secure = True, samesite = "strict")
                return reponse
            else:
                # This shouldn't happen,
                logout_user()
                error_for(endpoint="views.static_html", message="OAuth provider ddin't return valid access token")
                return redirect(url_for("auth.login"))

        except Exception as e:
            # If logged out will raise an exception
            logout_user()
            error_for(endpoint="views.static_html", message=str(e))
            return redirect(url_for("auth.login"))


    @plugin_bp.route('/admin/sso')
    @admins_only
    def sso_list():
        return render_template('list.html')


    @plugin_bp.route('/admin/sso/client/<int:client_id>', methods = ['GET', 'POST', 'DELETE'])
    @admins_only
    def sso_details(client_id):
        if request.method == 'DELETE':
            client = OAuthClients.query.filter_by(id=client_id).first()
            if client:
                client.disconnect(oauth)
                db.session.delete(client)
                db.session.commit()
                db.session.flush()
            return redirect(url_for('sso.sso_list'))
        elif request.method == "POST":
            client = OAuthClients.query.filter_by(id=client_id).first()
            client.client_id = request.form["client_id"]
            client.client_secret = request.form["client_secret"]
            client.access_token_url = request.form["access_token_url"]
            client.authorize_url = request.form["authorize_url"]
            client.api_base_url = request.form["api_base_url"]
            client.server_metadata_url = request.form["server_metadata_url"]
            client.color = request.form["color"]
            client.enabled = ("enabled" in request.form and request.form["enabled"] == "y")
            db.session.commit()
            db.session.flush()
            client.register(oauth)

            return redirect(url_for('sso.sso_list'))
        else:
          client = OAuthClients.query.filter_by(id=client_id).first()
          form = OAuthForm()
          form.name.data = client.name
          form.client_id.data = client.client_id
          form.client_secret.data = client.client_secret
          form.access_token_url.data = client.access_token_url
          form.authorize_url.data = client.authorize_url
          form.api_base_url.data = client.api_base_url
          form.server_metadata_url.data = client.server_metadata_url
          form.color.data = client.color
          form.enabled.data = client.enabled
          form.submit.label.text = "Update"

          return render_template('update.html', form=form)


    @plugin_bp.route('/admin/sso/create', methods = ['GET', 'POST'])
    @admins_only
    def sso_create():
        if request.method == "POST":
            name = request.form["name"]
            client_id = request.form["client_id"]
            client_secret = request.form["client_secret"]
            access_token_url = request.form["access_token_url"]
            authorize_url = request.form["authorize_url"]
            api_base_url = request.form["api_base_url"]
            server_metadata_url = request.form["server_metadata_url"]
            color = request.form["color"]
            enabled = ("enabled" in request.form and request.form["enabled"] == "y")
            client = OAuthClients(
                name=name,
                client_id=client_id,
                client_secret=client_secret,
                access_token_url=access_token_url,
                authorize_url=authorize_url,
                api_base_url=api_base_url,
                server_metadata_url=server_metadata_url,
                color=color,
                enabled=enabled
            )
            db.session.add(client)
            db.session.commit()
            db.session.flush()

            client.register(oauth)

            return redirect(url_for('sso.sso_list'))

        form = OAuthForm()
        return render_template('create.html', form=form)


    @plugin_bp.route("/sso/login/<int:client_id>", methods = ['GET'])
    def sso_oauth(client_id):
        client = oauth.create_client(client_id)
        redirect_uri=url_for('sso.sso_redirect', client_id=client_id, _external=True, _scheme='https')
        return client.authorize_redirect(redirect_uri)


    @plugin_bp.route("/sso/redirect/<int:client_id>", methods = ['GET'])
    def sso_redirect(client_id):
        try:
            client = oauth.create_client(client_id)
            token = client.authorize_access_token()
        except Exception as e:
            error_for(endpoint="auth.login", message=str(e))
            return redirect(url_for("auth.login"))

        try:
            api_data = client.get('').json()
        except:
            api_data = []
        try:
            userinfo = client.parse_id_token(token)
        except:
            userinfo = []

        if "email" in api_data:
            user_email = api_data["email"]
        elif "email" in userinfo :
            user_email = userinfo["email"]
        else:
            user_email = "unknown@example.com"

        if "preferred_username" in api_data:
            user_name = api_data["preferred_username"]
        if "preferred_username" in userinfo:
            user_name = userinfo["preferred_username"]
        elif user_email.find("@") == -1:
            user_name = user_email
        else:
            user_name = user_email[:user_email.find("@")]

        if process_boolean_str(get_app_config("OAUTH_HAS_ROLES")):
            user_roles = api_data.get("roles")
        else:
            user_roles = None;

        user = Users.query.filter_by(name=user_name).first()
        if user is None:
            # Check if we are allowing registration before creating users
            if registration_visible():
                user = Users(
                    name=user_name,
                    email=user_email,
                    verified=True,
                )
                db.session.add(user)
                db.session.commit()
            else:
                log("logins", "[{date}] {ip} - Public registration via MLC blocked")
                error_for(
                    endpoint="auth.login",
                    message="Public registration is disabled. Please try again later.",
                )
                return redirect(url_for("auth.login"))

        user.verified = True
        db.session.commit()

        if user_roles is not None and len(user_roles) > 0 and user_roles[0] in ["admin", "user"]:
            user_role = user_roles[0]
            if user_role != user.type:
                user.type = user_role
                db.session.commit()
                user = Users.query.filter_by(email=user_email).first()
                clear_user_session(user_id=user.id)

        login_user(user)

        if request.headers.get("X-Forwarded-Prefix"):
            path = request.headers.get("X-Forwarded-Prefix")
        else:
            path = "/"
        response = redirect(url_for("challenges.listing"))
        response.set_cookie("sso_client_id", str(client_id), path = path, httponly = True, secure = True, samesite = "strict")
        response.set_cookie("token", str(token), path = path, httponly = True, secure = True, samesite = "strict")
        if process_boolean_str(get_app_config("OAUTH_SSO_LOGOUT")):
            # Save end_session_endpoint for logout function
            metadata = client.load_server_metadata()
            response.set_cookie("end_session_endpoint", metadata["end_session_endpoint"], path = path, httponly = True, secure = True, samesite = "strict")

        return response


    @plugin_bp.route("/sso/logout", methods = ['GET'])
    def sso_logout():
        if current_user.authed():
            logout_user()

        redirect_url = url_for("views.static_html")
        token = request.cookies.get("token")
        if token:
            id_token = json.loads(token.replace("'", '"'))["id_token"]
            end_session_endpoint = request.cookies.get("end_session_endpoint")
            if id_token and end_session_endpoint:
                return redirect(end_session_endpoint + "?id_token_hint=" + id_token + "&post_logout_redirect_uri=" + redirect_url)
            else:
                error_for(endpoint="views.static_html", message="No id_token or end_session_endpoint for SSO logout")
                return redirect(redirect_url)
        else:
            error_for(endpoint="views.static_html", message="No token or userinfo cookie for SSO logout")
            return redirect(redirect_url)

    return plugin_bp
