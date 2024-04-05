from flask import Flask, Response, render_template, request
import binascii
import hashlib
import hmac
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from requests.auth import AuthBase
from requests import Session

app = Flask(__name__)

# PUBLIC_KEY = "735c7b0e-c756-4542-ba81-334f0a253cc4"
# PRIVATE_KEY = "df29a01ef859e0feb6597facecd9835c32eb455675b7e067b9f5d95e26694c01"
# PRIVATE_KEY = "df29a01ef859e0feb6597facecb9835c32eb455675b7e067b9f5d95e26694c01"


class MyClient(Session):
    """Client with specialized auth required by api."""

    def __init__(self, public_key, private_key):
        # allow passing args to `Session.__init__`
        super().__init__()

        # `self.auth` callable that creates timestamp when request is made
        self.auth = SparcoAuth(public_key, private_key)


class SparcoAuth(AuthBase):
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def __call__(self, r):
        timestamp = (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")  # UTC time in ISO8601
        )
        signature = self._generate_signature(r, timestamp)
        r.headers.update({
            "sparco-publickey": self.public_key,
            "sparco-timestamp": timestamp,
            "sparco-signature": signature
        })

        return r

    def _generate_signature(self, r, timestamp):
        uri = r.url.replace("https://", "").replace("http://", "")
        uri = urllib.parse.quote(
            uri, safe=""
        ).lower()  # URL encode first and lower() after encode
        if r.body:
            # Append hash of content
            body = r.body
            if isinstance(body, str):
                body = body.encode('utf-8')

            content_hash = hashlib.md5(body).hexdigest().upper()  # noqa: S324
            data = f"{uri}|{content_hash}&publicKey={self.public_key}&timeStamp={timestamp}"
        else:
            data = f"{uri}&publicKey={self.public_key}&timeStamp={timestamp}"

        key = binascii.unhexlify(self.private_key)
        signature = hmac.new(key, data.encode(), hashlib.sha256).hexdigest().upper()

        return signature


@app.route('/')
def home():
    return render_template('key_form.html')


@app.route('/external-redirect/', methods=['POST'])
def redirect_login():
    public_key = request.form['public-key']
    private_key = request.form['private-key']
    uri = request.form['uri']

    if not all([public_key, private_key, uri]):
        raise RuntimeError('Please provide data')

    session = MyClient(public_key, private_key)
    r = session.get(uri, allow_redirects=True)

    flask_response = Response(r.content, 302)
    for cookie_key, cookie_val in session.cookies.get_dict().items():
        flask_response.set_cookie(cookie_key, cookie_val)
    flask_response.headers["Location"] = uri.split('/api/Vitality')[0]
    return flask_response


if __name__ == '__main__':
    app.run(debug=True)
