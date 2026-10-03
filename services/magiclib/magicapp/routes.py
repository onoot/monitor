from flask import session, render_template, url_for, redirect, request, render_template_string, make_response, send_file, flash, jsonify
from magicapp import app, db
from flask_session import Session
import json
import base64
from itertools import cycle
from functools import wraps

def login_required(f):
    """Декоратор для проверки авторизации пользователя"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged' not in session or not session['logged']:
            flash('Для доступа к этой странице необходимо авторизоваться')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def xor_strings(str1, str2):
    """Правильная XOR функция без обрезания пароля"""
    if not str1 or not str2:
        return ""
    
    # Преобразуем строки в байты
    bytes1 = str1.encode('utf-8')
    bytes2 = str2.encode('utf-8')
    
    # Используем cycle для бесконечного повторения magic_word
    result = bytearray()
    bytes2_cycle = cycle(bytes2)
    
    # Обрабатываем ВСЕ байты пароля
    for byte1 in bytes1:
        byte2 = next(bytes2_cycle)
        result.append(byte1 ^ byte2)
    
    return base64.b64encode(result).decode('utf-8')

@app.route('/')
@app.route('/index', methods=['GET'])
def register():
    if 'logged' in session and session['logged']:
        return redirect(url_for('startscreen'))
    return render_template('reg.html', err=request.args.get('err'))

@app.route('/index', methods=['POST'])
def register_post():
    if 'logged' in session and session['logged']:
        return redirect(url_for('startscreen'))
    username = request.form.get('username')
    password = request.form.get('password')
    magic_word = request.form.get('magicword')
    if db.get_user_by_name(username) != None:
        return redirect(url_for('register', err=1))
    user_id = db.insert_user(username, password, magic_word)
    if user_id:
        if isinstance(user_id, tuple):
            user_id = user_id[0]
        session['user_id'] = user_id
        session['logged'] = True
        session['username'] = username
        return redirect(url_for('startscreen'))

@app.route('/login', methods=['GET'])
def login():
    if 'logged' in session and session['logged']:
        return redirect(url_for('index'))
    return render_template('auth.html', err=request.args.get('err'))

@app.route('/login', methods=['POST'])
def login_post():
    if 'logged' in session and session['logged']:
        return redirect(url_for('startscreen'))
    username = request.form.get('username')
    password = request.form.get('password')
    user = db.get_user_by_name(username)
    if user:
        user_id = user[0]
        session['user_id'] = user_id
        session['logged'] = True
        session['username'] = user[1]
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('startscreen'))
    return redirect(url_for('login', err=1))

@app.route("/students",  methods=['GET'])
@login_required
def index():
    try:
        data = db.get_all_users()
        return render_template("index.html", data=data, xor_strings=xor_strings)
    except Exception as e:
        app.logger.error(f"Error in students route: {e}")

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    session.clear()
    flash('Вы успешно вышли из системы')
    return redirect(url_for('login'))

@app.route('/startscreen')
@login_required
def startscreen():
    return render_template('startscreen.html')

@app.route('/library')
@login_required
def library():
    return render_template('lib.html')

@app.route('/api-dev/users', methods=['GET'])
@login_required
def get_users():
    try:
        user_id = session.get('user_id')
        app.logger.debug(f"User ID from session: {user_id}, type: {type(user_id)}")
        if not user_id:
            return jsonify({'error': 'Пользователь не найден'}), 404
        user = db.get_user_by_id(user_id)
        app.logger.debug(f"User from DB: {user}")
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404
        username = user[1]
        app.logger.debug(f"Username: {username}, checking access...")
        users = db.get_all_users()
        if username not in ['Albus Dumbledore']:
            return jsonify({'list': users if users else []})
        return jsonify({'list': users if users else []})
        
    except Exception as e:
        app.logger.error(f"Error in get_users: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def page_not_found(e):
    error_page = open('magicapp/templates/404.html').read().replace('_PATH_', request.path)
    return render_template_string(error_page), 404
