from flask import Flask, redirect, url_for, session, request, render_template
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth
import os

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'sua_chave_secreta_aqui')  # Substitua por uma chave secreta

# Credenciais do SUAP
client_id = os.getenv('SUAP_CLIENT_ID', 'SEU_CLIENT_ID')
client_secret = os.getenv('SUAP_CLIENT_SECRET', 'SEU_CLIENT_SECRET')
authorization_base_url = 'https://suap.ifrn.edu.br/o/authorize/'
token_url = 'https://suap.ifrn.edu.br/o/token/'
redirect_uri = 'http://localhost:5000/login/authorized'

# Endpoint da API do SUAP para perfil e boletim
perfil_url = 'https://suap.ifrn.edu.br/api/v2/minhas-informacoes/meus-dados/'
boletim_url = 'https://suap.ifrn.edu.br/api/v2/minhas-informacoes/boletim/'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    suap = OAuth2Session(client_id, redirect_uri=redirect_uri)
    authorization_url, state = suap.authorization_url(authorization_base_url)

    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/login/authorized')
def callback():
    suap = OAuth2Session(client_id, state=session['oauth_state'], redirect_uri=redirect_uri)
    token = suap.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url, auth=HTTPBasicAuth(client_id, client_secret))

    session['oauth_token'] = token
    return redirect(url_for('.profile'))

@app.route('/profile')
def profile():
    suap = OAuth2Session(client_id, token=session['oauth_token'])
    response = suap.get(perfil_url)

    if response.status_code == 200:
        user_info = response.json()
        return render_template('profile.html', user=user_info)
    else:
        return 'Erro ao acessar o perfil do usuário'

@app.route('/boletim')
def boletim():
    suap = OAuth2Session(client_id, token=session['oauth_token'])
    ano_letivo = request.args.get('ano_letivo', '2024')
    periodo_letivo = request.args.get('periodo_letivo', '1')

    response = suap.get(f"{boletim_url}{ano_letivo}/{periodo_letivo}/")

    if response.status_code == 200:
        boletim_data = response.json()
        return render_template('boletim.html', boletim=boletim_data)
    else:
        return 'Erro ao acessar o boletim'

if __name__ == "__main__":
    app.run(debug=True)
