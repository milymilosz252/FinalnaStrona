from flask import Flask, render_template, request, redirect, session, flash, send_from_directory, send_file, url_for, redirect
from flask_mail import Mail, Message
import hashlib
import random
import string
import datetime
import os
import zipfile
from PIL import Image
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Konfiguracja do wysyłania e-maili
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'twojemail@gmail.com'
app.config['MAIL_PASSWORD'] = 'twojehaslo'
app.config['MAIL_DEFAULT_SENDER'] = 'twojemail@gmail.com'
UPLOAD_FOLDER = 'zdjecia'
WEBP_FOLDER = 'WebP'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['WEBP_FOLDER'] = WEBP_FOLDER

mail = Mail(app)

# Funkcja do odczytu danych użytkowników z pliku
def read_user_data():
    user_data = {}
    with open('users.login', 'r') as file:
        for line in file:
            email, password_hash, auth_code, created_at, verified = line.strip().split(',')
            user_data[email] = {'password_hash': password_hash, 'auth_code': auth_code, 'created_at': datetime.datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S'), 'verified': verified == 'True'}
    return user_data

# Funkcja do zapisu danych użytkowników do pliku
def write_user_data(user_data):
    with open('users.login', 'w') as file:
        for email, data in user_data.items():
            verified = 'True' if data['verified'] else 'False'
            file.write(f"{email},{data['password_hash']},{data['auth_code']},{data['created_at'].strftime('%Y-%m-%d %H:%M:%S')},{verified}\n")

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def compress_images(folder):
    file_paths = [os.path.join(folder, filename) for filename in os.listdir(folder)]
    with zipfile.ZipFile(f'{folder}.zip', 'w') as zip_file:
        for file_path in file_paths:
            zip_file.write(file_path, os.path.basename(file_path))

def convert_to_webp(input_path, output_path, quality=24):
    try:
        im = Image.open(input_path)
        im.save(output_path, quality=quality, lossless=False)
        return True
    except Exception as e:
        print(f"Conversion failed for {input_path}: {str(e)}")
        return False

def save_image_names(folder,username, filenames):
    with open('img.names', 'a') as f:
        for filename in filenames:
            f.write(f"{username}: {filename}\n")




def get_file_name(filename):
    return os.path.splitext(filename)[0]

app.jinja_env.filters['get_file_name'] = get_file_name

# Trasa rejestracji
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        
        # Sprawdzenie czy adres e-mail ma właściwą domenę
        if not email.endswith('@1lo.pl'):
            return "Nie można zarejestrować się na adresy e-mail spoza domeny @1lo.pl."

        # Sprawdzenie czy użytkownik już istnieje
        user_data = read_user_data()
        if email in user_data:
            return "Konto o podanym adresie e-mail już istnieje."

        password = request.form['password']
        auth_code = ''.join(random.choices(string.digits, k=6))  # Generowanie losowego 6-cyfrowego kodu
        password_hash = hashlib.sha256(password.encode()).hexdigest()  # Haszowanie hasła

        user_data[email] = {'password_hash': password_hash, 'auth_code': auth_code, 'created_at': datetime.datetime.now(), 'verified': False}
        write_user_data(user_data)

        # Wysyłanie e-maila z kodem autoryzacyjnym
        msg = Message('Kod autoryzacyjny', recipients=[email])
        msg.body = f'Twój kod autoryzacyjny: {auth_code}'
        mail.send(msg)

        session['email'] = email  # Zapamiętaj adres e-mail w sesji
        return redirect('/verify')
    return render_template('register.html')

# Trasa weryfikacji kodu autoryzacyjnego
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'logged_in' in session:
        if request.method == 'POST':
            email = session['email']
            auth_code = request.form['auth_code']
            
            # Sprawdzenie czy kod autoryzacyjny jest poprawny
            user_data = read_user_data()
            if email in user_data and user_data[email]['auth_code'] == auth_code \
                and datetime.datetime.now() - user_data[email]['created_at'] < datetime.timedelta(minutes=5):
                # Kod autoryzacyjny jest poprawny i nie wygasł
                user_data[email]['verified'] = True
                write_user_data(user_data)
                return "Kod autoryzacyjny poprawny. Konto zostało zweryfikowane.", redirect('/index')
            else:
                return "Nieprawidłowy kod autoryzacyjny lub kod wygasł."

        return render_template('verify.html')
    else:
        return redirect('/')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        
        user_data = read_user_data()
        if email in user_data:
            # Generowanie i zapisanie kodu weryfikacyjnego do bazy danych
            auth_code = ''.join(random.choices(string.digits, k=6))  # Generowanie losowego 6-cyfrowego kodu
            user_data[email]['auth_code'] = auth_code
            write_user_data(user_data)

            # Wysłanie e-maila z kodem weryfikacyjnym
            msg = Message('Resetowanie hasła - Kod weryfikacyjny', recipients=[email])
            msg.body = f'Kod weryfikacyjny do zresetowania hasła: {auth_code}'
            mail.send(msg)

            # Przekierowanie użytkownika do formularza wprowadzenia kodu weryfikacyjnego
            session['reset_email'] = email
            return redirect('/verify_reset_code')
        else:
            return "Nie ma konta przypisanego do podanego adresu e-mail."

    return render_template('reset_password.html')

@app.route('/verify_reset_code', methods=['GET', 'POST'])
def verify_reset_code():
    if request.method == 'POST':
        email = session.get('reset_email')
        if not email:
            return redirect('/reset_password')

        auth_code = request.form['auth_code']
        
        # Sprawdzenie czy kod weryfikacyjny jest poprawny
        user_data = read_user_data()
        if email in user_data and user_data[email]['auth_code'] == auth_code:
            # Kod weryfikacyjny jest poprawny
            session['reset_email'] = email  # Zapamiętaj adres e-mail w sesji
            return redirect('/change_password')
        else:
            return "Nieprawidłowy kod weryfikacyjny."

    return render_template('verify_reset_code.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    email = session.get('reset_email')
    if not email:
        return redirect('/reset_password')

    if request.method == 'POST':
        new_password = request.form['new_password']

        # Zmiana hasła użytkownika w bazie danych
        user_data = read_user_data()
        user_data[email]['password_hash'] = hashlib.sha256(new_password.encode()).hexdigest()
        write_user_data(user_data)
        return redirect('/')
    return render_template('change_password.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['submit_button'] == 'Zaloguj':
            username = request.form['username']
            password = request.form['password']
            user_data = read_user_data()
            if username in user_data and user_data[username]['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
                session['logged_in'] = True
                session['username'] = username  # Set 'username' in session to the username value
                session['email'] = username
                return redirect('/index')
            else:
                return "Błędne dane logowania"
    return render_template('login.html', username=session.get('username', None))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect('/')

# Tutaj zaczynają się faktyczne podstrony widoczne juz po zalogowaniu

@app.route('/index')
def index():
    if 'logged_in' in session:
        email = session['email']
        user_data = read_user_data()
        if not user_data[email]['verified']:
            return redirect('/verify')
        else:
            return render_template('index.html', username=session['username'])
    else:
        return redirect('/')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'logged_in' not in session:
        flash('Musisz być zalogowany, aby przesłać pliki.', 'error')
        return redirect(url_for('login'))

    email = session['email']
    user_data = read_user_data()
    if not user_data[email]['verified']:
        flash('Musisz zweryfikować swoje konto, aby przesłać pliki.', 'error')
        return redirect('/verify')

    if 'file' not in request.files:
        flash('Brak pliku w formularzu!', 'error')
        return redirect(request.url)

    files = request.files.getlist('file')
    uploaded_filenames = []  # Lista nazw przesłanych plików

    for file in files:
        if file.filename == '':
            flash('Brak wybranego pliku!', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            # Konwersja do WebP
            webp_filename = secure_filename(os.path.splitext(filename)[0] + '.webp')
            webp_path = os.path.join(app.config['WEBP_FOLDER'], webp_filename)
            convert_to_webp(file_path, webp_path)
            uploaded_filenames.append(filename)  # Dodaj nazwę przesłanego pliku do listy
        else:
            flash('Niedozwolone rozszerzenie pliku!', 'error')
            return redirect(request.url)

    # Zapisz nazwy przesłanych plików do pliku img.names
    if uploaded_filenames:
        save_image_names(app.config['UPLOAD_FOLDER'], session['username'], uploaded_filenames)

    # Po zakończeniu przesyłania, kompresujemy przesłane pliki
    compress_images(UPLOAD_FOLDER)
    # Przekierowanie użytkownika na stronę główną po przesłaniu plików
    flash('Pliki zostały pomyślnie przesłane.', 'success')
    return redirect(url_for('gallery'))



@app.route('/galeria')
def gallery():
    if 'logged_in' not in session:
        return redirect('/')
    else:
        username = session.get('username')
        webp_images = os.listdir(app.config['WEBP_FOLDER'])
        return render_template('gallery.html', webp_images=webp_images, username=username)

@app.route('/webp_images/<filename>')
def send_webp_image(filename):
    return send_from_directory(app.config['WEBP_FOLDER'], filename)

@app.route('/download', methods=['GET'])
def download():
    return send_file('zdjecia.zip', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
