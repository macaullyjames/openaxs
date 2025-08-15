import requests


class APIClient:
    def __init__(self, auth_token=None, base_url="https://api.accessy.se"):
        self.session = requests.Session()
        self.session.headers.update({
            "authorization": f"Bearer {auth_token}"
        })
        self.base_url = base_url

    def get(self, path, **kwargs):
        return self.session.get(self.base_url + path, **kwargs)

    def post(self, path, **kwargs):
        return self.session.post(self.base_url + path, **kwargs)

    def put(self, path, **kwargs):
        return self.session.put(self.base_url + path, **kwargs)

    # add .put, .delete if needed
