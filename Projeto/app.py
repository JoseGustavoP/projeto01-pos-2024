from flask import Flask, redirect, url_for, session, request, render_template, flash
from authlib.integrations.flask_client import OAuth
import logging
import requests

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
            session['user_data'] = user_data  # Store user data in the session
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
    

def get_boletim(ano_letivo, periodo_letivo):
    token = session.get('suap_token', {}).get('access_token')
    if not token:
        return None

    headers = {
        "Authorization": f"Bearer {token}"
    }

    boletim_url = f"https://suap.ifrn.edu.br/api/v2/minhas-informacoes/boletim/{ano_letivo}/{periodo_letivo}/"
    response = requests.get(boletim_url, headers=headers)

    if response.status_code == 401:  # Se o token estiver expirado
        new_token = refresh_token()
        if new_token:
            headers["Authorization"] = f"Bearer {new_token}"
            response = requests.get(boletim_url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        logging.error(f"Erro ao obter o boletim: {response.status_code} - {response.text}")
        return None

def refresh_token():
    token = session.get('suap_token', {}).get('refresh_token')
    if not token:
        return None

    refresh_url = "https://suap.ifrn.edu.br/api/v2/autenticacao/token/refresh/"
    response = requests.post(refresh_url, data={"refresh": token})

    if response.status_code == 200:
        new_token = response.json().get("access")
        if new_token:
            session['suap_token']['access_token'] = new_token
            return new_token
    logging.error(f"Erro ao renovar o token: {response.status_code} - {response.text}")
    return None

@app.route('/boletim')
def boletim():
    if 'suap_token' in session:
        try:
            anos = list(range(2020, 2025))  
            ano_selecionado = request.args.get('ano', str(anos[-1]))  # Pega o ano da query string ou o mais recente
            periodo_letivo = 1  # Exemplo: período letivo fixo

            # Obtendo os dados do boletim do SUAP
            boletim_data = get_boletim(ano_selecionado, periodo_letivo)
            
            if boletim_data:
                logging.info(f"Boletim do ano {ano_selecionado} recebido com sucesso.")
            else:
                flash('Nenhum boletim encontrado ou erro ao buscar o boletim.')
            
            return render_template(
                'boletim.html',
                boletim=boletim_data,
                anos=anos, 
                ano_selecionado=ano_selecionado,
                user_data=session.get('user_data', {})
            )
        except Exception as e:
            logging.error(f"Erro ao buscar o boletim: {e}")
            flash('Falha ao buscar os dados. Tente novamente mais tarde.')
            return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()
