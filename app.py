from flask import Flask, render_template, request
import binascii
import hashlib
import hmac
from datetime import datetime, timezone

app = Flask(__name__)

# PUBLIC_KEY = "735c7b0e-c756-4542-ba81-334f0a253cc4"
# PRIVATE_KEY = "df29a01ef859e0feb6597facecd9835c32eb455675b7e067b9f5d95e26694c01"
# PRIVATE_KEY = "df29a01ef859e0feb6597facecb9835c32eb455675b7e067b9f5d95e26694c01"

# PUBLIC_KEY = "c56c3bc3-8773-4dae-83b4-5dbbb20f287d"
# PRIVATE_KEY = "4cf3602c32161ad0002863eceb6bea5cb92129045734e397507e2c7f27ce5a3f"
# uri = 'https://acc.incentives.asr.nl/api/Vitality/SingleSignOn/roi/fehowf/krisztian/'


def _generate_signature(url, timestamp, public_key, private_key, common_auth_id):
    if not url.endswith('/'):
        url += '/'

    if common_auth_id:
        url += '%s/' % common_auth_id

    data = f"{url}&publicKey={public_key}&timeStamp={timestamp}"

    key = binascii.unhexlify(private_key)
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
    common_auth_id = request.form['common-auth-id']

    if not all([public_key, private_key, uri]):
        raise RuntimeError('Please provide data')

    timestamp = (
        datetime.now(timezone.utc)
        .isoformat("T", "seconds")
        .replace("+00:00", "")
    )
    signature = _generate_signature(uri, timestamp, public_key, private_key, common_auth_id)
    return f'timestamp: {timestamp}, signature: {signature}'


if __name__ == '__main__':
    app.run(debug=True)
