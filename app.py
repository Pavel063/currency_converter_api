from flask import Flask, request, render_template, jsonify
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
import sqlite3
import requests

app = Flask(__name__)
DB = 'converter.db'
API_BASE = 'https://api.frankfurter.dev/v2'
# Frankfurter supports both pinned official providers and an aggregated feed.
# ECB is the default for standard currencies; RUB and KZT use their national sources.
API_PROVIDER = 'ecb'

# Fallback list used only to build the selectors if the API is temporarily unavailable.
CURRENCIES = {
    'EUR': 'Евро', 'USD': 'Доллар США', 'GBP': 'Фунт стерлингов',
    'RUB': 'Российский рубль', 'KZT': 'Казахстанский тенге',
    'CNY': 'Китайский юань', 'JPY': 'Японская иена',
    'CHF': 'Швейцарский франк', 'PLN': 'Польский злотый'
}


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        amount REAL,
        src TEXT,
        dst TEXT,
        result REAL,
        rate REAL,
        rate_date TEXT
    )''')
    # Upgrade databases created by the previous version.
    columns = {row['name'] for row in conn.execute('PRAGMA table_info(history)').fetchall()}
    if 'rate' not in columns:
        conn.execute('ALTER TABLE history ADD COLUMN rate REAL')
    if 'rate_date' not in columns:
        conn.execute('ALTER TABLE history ADD COLUMN rate_date TEXT')
    conn.commit()
    conn.close()


def fetch_rate(src: str, dst: str):
    """Return (rate, date, provider) using the most relevant official source.

    ECB is used for the standard currencies. RUB is requested from the
    Central Bank of Russia (CBR), and KZT from the National Bank of Kazakhstan
    (NBK). If a provider-specific pair is unavailable, the general Frankfurter
    endpoint is used as a fallback.
    """
    if src == dst:
        today = datetime.now(timezone.utc).date().isoformat()
        return Decimal('1'), today, 'Без запроса к API (одинаковые валюты)'

    # Use the provider associated with the special currency in the pair.
    # When RUB and KZT are both selected, use the aggregated official feed
    # because neither single-country provider is guaranteed to publish every
    # RUB/KZT cross-rate.
    provider = API_PROVIDER
    provider_label = 'European Central Bank (ECB) через Frankfurter'
    if src == 'RUB' and dst != 'KZT' or dst == 'RUB' and src != 'KZT':
        provider = 'cbr'
        provider_label = 'Центральный банк России (CBR) через Frankfurter'
    elif src == 'KZT' and dst != 'RUB' or dst == 'KZT' and src != 'RUB':
        provider = 'nbk'
        provider_label = 'Национальный банк Казахстана (NBK) через Frankfurter'

    if src == 'RUB' and dst == 'KZT' or src == 'KZT' and dst == 'RUB':
        provider = None
        provider_label = 'Frankfurter — агрегированные официальные источники'

    if provider:
        url = f'{API_BASE}/providers/{provider}/rate/{src.lower()}/{dst.lower()}'
    else:
        url = f'{API_BASE}/rate/{src.lower()}/{dst.lower()}'

    try:
        response = requests.get(url, timeout=8)
        response.raise_for_status()
        data = response.json()
        return Decimal(str(data['rate'])), data['date'], provider_label
    except (requests.RequestException, KeyError, ValueError, InvalidOperation):
        # Fallback to Frankfurter's aggregated official-source feed.
        fallback = f'{API_BASE}/rate/{src.lower()}/{dst.lower()}'
        response = requests.get(fallback, timeout=8)
        response.raise_for_status()
        data = response.json()
        return Decimal(str(data['rate'])), data['date'], 'Frankfurter — агрегированные официальные источники'


@app.route('/')
def index():
    return render_template('index.html', currencies=CURRENCIES)


@app.route('/convert', methods=['POST'])
def convert():
    data = request.get_json(silent=True) or request.form

    try:
        amount = Decimal(str(data.get('amount', '0')))
    except (InvalidOperation, TypeError, ValueError):
        return jsonify({'error': 'Некорректная сумма'}), 400

    src = str(data.get('src', 'EUR')).upper()
    dst = str(data.get('dst', 'USD')).upper()

    if src not in CURRENCIES or dst not in CURRENCIES:
        return jsonify({'error': 'Неизвестная валюта'}), 400
    if amount < 0 or amount > Decimal('1000000000'):
        return jsonify({'error': 'Сумма вне допустимого диапазона'}), 400

    try:
        rate, rate_date, provider = fetch_rate(src, dst)
    except (requests.RequestException, KeyError, ValueError, InvalidOperation) as exc:
        app.logger.warning('Currency API error: %s', exc)
        return jsonify({'error': 'Не удалось получить актуальный курс. Проверьте подключение к интернету.'}), 502

    result = amount * rate
    user = str(request.args.get('user', 'guest'))[:100]

    conn = get_db()
    conn.execute(
        'INSERT INTO history(user, amount, src, dst, result, rate, rate_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (user, float(amount), src, dst, float(result), float(rate), rate_date)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'result': float(result.quantize(Decimal('0.01'))),
        'rate': float(rate),
        'rate_date': rate_date,
        'provider': provider,
        'src': src,
        'dst': dst
    })


# Учебная уязвимость №1: SQL-инъекция в демонстрационном endpoint.
@app.route('/vulnerable/search')
def vulnerable_search():
    username = request.args.get('user', 'guest')
    conn = get_db()
    query = f"SELECT id, user, amount, src, dst, result FROM history WHERE user = '{username}'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


# Учебная уязвимость №2: отражённый XSS в демонстрационном endpoint.
@app.route('/vulnerable/greet')
def vulnerable_greet():
    name = request.args.get('name', 'Гость')
    return f'<h2>Здравствуйте, {name}!</h2><p>Это специально уязвимый учебный endpoint.</p>'


# Учебная уязвимость №3: отсутствие контроля доступа к истории.
@app.route('/vulnerable/history/<int:user_id>')
def vulnerable_history(user_id):
    conn = get_db()
    rows = conn.execute(
        'SELECT id, user, amount, src, dst, result, rate, rate_date FROM history WHERE id = ?',
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route('/api/rates')
def rates():
    """Return live EUR rates from Frankfurter using official-source data."""
    try:
        response = requests.get(
            f'{API_BASE}/rates',
            params={'base': 'EUR', 'quotes': ','.join(CURRENCIES.keys())},
            timeout=8,
        )
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
        return jsonify({'error': str(exc)}), 502


if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)
