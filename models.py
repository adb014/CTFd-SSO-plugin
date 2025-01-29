from CTFd.config import process_boolean_str
from CTFd.models import db
from CTFd.utils import get_app_config
import json

def fetch_token():
    return request.cookies.get("token")

class OAuthClients(db.Model):
    __tablename__ = "oauth_clients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    client_id = db.Column(db.Text)
    client_secret = db.Column(db.Text)
    access_token_url = db.Column(db.Text)
    authorize_url = db.Column(db.Text)
    api_base_url = db.Column(db.Text)
    server_metadata_url = db.Column(db.Text)

    # In a later update you will be able to customize the login button 
    color = db.Column(db.Text)
    icon = db.Column(db.Text)

    # Allow the OAuth provider to be individually enabled/disabled
    enabled = db.Column(db.Boolean, default=False)

    def register(self, oauth):
        if process_boolean_str(get_app_config("OAUTH_HAS_ROLES")):
          scope = 'profile openid  roles'
        else:
          scope = 'profile openid email'

        oauth.register(
            name=self.id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            access_token_url=self.access_token_url,
            authorize_url=self.authorize_url,
            api_base_url=self.api_base_url,
            server_metadata_url=self.server_metadata_url,
            fetch_token=fetch_token,
            client_kwargs={'scope': scope}
        )

    def disconnect(self, oauth):
        oauth._registry[self.id] = None
        oauth._clients[self.id] = None

    def json(self):
        return {'id': self.id, 
                'name': self.name,
                'client_id' : self.client_id,
                'client_secret': self.client_secret,
                'access_token_url': self.access_token_url,
                'authorize_url': self.authorize_url,
                'api_base_url': self.api_base_url,
                'server_metadata_url': self.server_metadata_url,
                'color': self.color,
                'icon': self.icon,
                'enabled': self.enabled}
