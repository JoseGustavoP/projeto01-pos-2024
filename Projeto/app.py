from flask import Flask, redirect, url_for, session, request, render_template, flash
from authlib.integrations.flask_client import OAuth
import logging

app = Flask(__name__)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

oauth.register(
    name='suap',
    client_id="O9nFwVfQzWWqXv4Vmkvs5nJ17tosNU45nZ3FX69d",
    client_secret="E9n0UmZRpy4FhfZjqQKlUP5dob6dLYntcnq11DMcBBBVioYrxUKyvdNFDvmGXnqu4uKE0yrb0c3Po4EUWqJ62QsZpMelXjSiUVmxaUCbJSLTIF8ZdU8HnLu9j5KH0zh5",
    api_base_url='https://suap.ifrn.edu.br/api/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://suap.ifrn.edu.br/o/token/',
    authorize_url='https://suap.ifrn.edu.br/o/authorize/',
    fetch_token=lambda: session.get('suap_token')
)
@app.route('/')
def index():
    if 'suap_token' in session:
        try:
            response = oauth.suap.get('v2/minhas-informacoes/meus-dados')
            response.raise_for_status()  # Raises an error for bad HTTP status
            user_data = response.json()
            print("User Data:", user_data)  # Debug print to check the data structure
            return render_template('user.html', user_data=user_data)
        except Exception as e:
            logging.error(f"Error fetching user data: {e}")
            flash('Failed to fetch user data. Please try again later.')
            return redirect(url_for('logout'))
    else:
        return render_template('index.html')


@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.suap.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.pop('suap_token', None)
    return redirect(url_for('index'))

@app.route('/login/authorized')
def auth():
    try:
        token = oauth.suap.authorize_access_token()
        session['suap_token'] = token
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error during authorization: {e}")
        flash('Authorization failed. Please try again.')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
