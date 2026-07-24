from flask import Flask, jsonify, request, session, send_from_directory, Response
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import os, csv, io, time
import bcrypt
from dotenv import load_dotenv
import pymongo

load_dotenv()

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'cf-dashboard-demo-key-2026')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

_allowed_origins = [o.strip() for o in os.environ.get(
    'ALLOWED_ORIGINS', 'http://localhost:20690,http://127.0.0.1:20690'
).split(',')]
CORS(app, origins=_allowed_origins, supports_credentials=True)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']         = 'SAMEORIGIN'
    return response

# ─── MongoDB connection ───────────────────────────────────────────────────────
_mongo_client = None
_mongo_db     = None

def _get_db():
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db
    try:
        _mongo_client = pymongo.MongoClient(
            host=os.environ.get('DB_HOST', '11.0.0.12'),
            port=int(os.environ.get('DB_PORT', 27018)),
            username=os.environ.get('DB_USER', 'tarsyer_admin'),
            password=os.environ.get('DB_PASS', ''),
            authSource='admin',
            directConnection=True,
            serverSelectionTimeoutMS=5000,
        )
        _mongo_client.admin.command('ping')
        _mongo_db = _mongo_client[os.environ.get('DB_NAME', 'cultfitServer')]
        print(f"[DB] Connected to MongoDB at {os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT')}")
    except Exception as exc:
        print(f"[DB] MongoDB connection failed: {exc}")
        _mongo_db = None
    return _mongo_db

PROJECT_NAME = 'Cultfit'

# ─── Auth ─────────────────────────────────────────────────────────────────────
# Password hash is for: Tarsyer@2026
_TARSYER_PASSWORD_HASH = '$2b$12$0wwgANOntm5QsPv15fkIf.T/6clHS8z3tlTm6bYNp8AyLtqhLvqDu'

_STATIC_USERS = {
    'cultfit@tarsyer.com': {
        'password_hash': _TARSYER_PASSWORD_HASH,
        'region': 'Cultfit',
        'role': 'analytics',
    },
}

_login_attempts: dict = {}
LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW_SECS  = 300

def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW_SECS]
    _login_attempts[ip] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        return False
    _login_attempts[ip].append(now)
    return True

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return wrapper

# ─── Auth routes ─────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    ip = request.remote_addr or '0.0.0.0'
    if not _check_rate_limit(ip):
        return jsonify({'success': False, 'message': 'Too many attempts. Try again later.'}), 429
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', ''))[:64]
    password = str(data.get('password', ''))[:256]

    user = _STATIC_USERS.get(username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        session.permanent = True
        session['user'] = username
        session['region'] = user['region']
        session['role'] = user['role']
        return jsonify({'success': True, 'username': username, 'region': user['region'], 'role': user['role']})

    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/me')
def me():
    if 'user' in session:
        return jsonify({
            'logged_in': True,
            'username': session['user'],
            'region': session.get('region', ''),
            'role': session.get('role', 'analytics'),
        })
    return jsonify({'logged_in': False})

# ─── Stores ──────────────────────────────────────────────────────────────────
_CF_STORES_FALLBACK = ['Cultfit-Mantri-Mall']

def _fetch_stores():
    db = _get_db()
    if db is None:
        return _CF_STORES_FALLBACK
    try:
        stores = db['footfall'].distinct('store_code', {'project_name': PROJECT_NAME})
        stores = sorted([s for s in stores if s])
        return stores if stores else _CF_STORES_FALLBACK
    except Exception:
        return _CF_STORES_FALLBACK

@app.route('/api/cultfit/stores')
@require_login
def cf_stores():
    return jsonify(_fetch_stores())

# ─── Shared date-range parsing ────────────────────────────────────────────────
def _parse_range():
    start_str = request.args.get('start')
    end_str   = request.args.get('end')
    store     = request.args.get('store', '')
    store     = '' if store in ('all', 'All', '') else store

    today = datetime.today()
    if start_str:
        try:    start_dt = datetime.strptime(start_str, '%Y-%m-%d')
        except: start_dt = today - timedelta(days=6)
    else:
        start_dt = today - timedelta(days=6)

    if end_str:
        try:    end_dt = datetime.strptime(end_str, '%Y-%m-%d')
        except: end_dt = today
    else:
        end_dt = today

    end_dt_inclusive = end_dt + timedelta(days=1)
    return start_dt, end_dt, end_dt_inclusive, store

# ─── Footfall (Male / Female — camera_no 1, count_child -> male) ─────────────
# ─── Passerby (Male / Female — camera_no 2, count+opp_count, staff->female, child->male)
def _footfall_exprs(category):
    if category == 'footfall':
        # male = count_male + count_child ; female = count_female
        male_expr = {'$add': [
            {'$ifNull': ['$count_male', 0]},
            {'$ifNull': ['$count_child', 0]},
        ]}
        female_expr = {'$ifNull': ['$count_female', 0]}
    else:
        # passerby: male = count_male + opp_count_male + count_child + opp_count_child
        #           female = count_female + opp_count_female + count_staff + opp_count_staff
        male_expr = {'$add': [
            {'$ifNull': ['$count_male', 0]},
            {'$ifNull': ['$opp_count_male', 0]},
            {'$ifNull': ['$count_child', 0]},
            {'$ifNull': ['$opp_count_child', 0]},
        ]}
        female_expr = {'$add': [
            {'$ifNull': ['$count_female', 0]},
            {'$ifNull': ['$opp_count_female', 0]},
            {'$ifNull': ['$count_staff', 0]},
            {'$ifNull': ['$opp_count_staff', 0]},
        ]}
    return male_expr, female_expr

@app.route('/api/cultfit/footfall')
@require_login
def cf_footfall():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()
    category = request.args.get('category', 'footfall')
    category = 'passerby' if category == 'passerby' else 'footfall'

    db = _get_db()
    if db is None:
        return jsonify({
            'total': 0, 'men': 0, 'women': 0,
            'hourly': [], 'daily': [], 'by_store': [],
            'db_connected': False,
        })

    try:
        collection = db['footfall']
        camera_no = 1 if category == 'footfall' else 2

        match_filter = {
            'project_name': PROJECT_NAME,
            'camera_no': camera_no,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            match_filter['store_code'] = store

        male_expr, female_expr = _footfall_exprs(category)

        # Hourly aggregation
        hourly_pipeline = [
            {'$match': match_filter},
            {'$addFields': {
                'hour_str': {'$substr': ['$date_time', 11, 2]},
                'male_v':   male_expr,
                'female_v': female_expr,
            }},
            {'$group': {
                '_id':    '$hour_str',
                'male':   {'$sum': '$male_v'},
                'female': {'$sum': '$female_v'},
            }},
            {'$sort': {'_id': 1}},
        ]
        hourly = [
            {'hour': f"{r['_id']}:00", 'male': r['male'], 'female': r['female'], 'total': r['male'] + r['female']}
            for r in collection.aggregate(hourly_pipeline)
        ]

        # Daily aggregation
        daily_pipeline = [
            {'$match': match_filter},
            {'$addFields': {
                'date_only': {'$substr': ['$date_time', 0, 10]},
                'male_v':    male_expr,
                'female_v':  female_expr,
            }},
            {'$group': {
                '_id':    '$date_only',
                'male':   {'$sum': '$male_v'},
                'female': {'$sum': '$female_v'},
            }},
            {'$sort': {'_id': 1}},
        ]
        daily = [
            {'date': r['_id'], 'male': r['male'], 'female': r['female'], 'total': r['male'] + r['female']}
            for r in collection.aggregate(daily_pipeline)
        ]

        # By-store aggregation
        store_pipeline = [
            {'$match': match_filter},
            {'$addFields': {'male_v': male_expr, 'female_v': female_expr}},
            {'$group': {
                '_id':   '$store_code',
                'total': {'$sum': {'$add': ['$male_v', '$female_v']}},
            }},
            {'$sort': {'total': -1}},
        ]
        by_store = [{'store': r['_id'], 'total': r['total']} for r in collection.aggregate(store_pipeline)]

        total_male   = sum(r['male']   for r in daily)
        total_female = sum(r['female'] for r in daily)

        return jsonify({
            'category': category,
            'total':    total_male + total_female,
            'men':      total_male,
            'women':    total_female,
            'hourly':   hourly,
            'daily':    daily,
            'by_store': by_store,
            'db_connected': True,
        })

    except Exception as exc:
        print(f"[DB] Footfall query error: {exc}")
        return jsonify({'error': 'Database query failed', 'detail': str(exc)}), 503

@app.route('/api/export/footfall')
@require_login
def export_footfall():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()
    category = request.args.get('category', 'footfall')
    category = 'passerby' if category == 'passerby' else 'footfall'
    db = _get_db()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Store', 'Male', 'Female', 'Total'])

    if db is not None:
        collection = db['footfall']
        camera_no = 1 if category == 'footfall' else 2
        match_filter = {
            'project_name': PROJECT_NAME,
            'camera_no': camera_no,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            match_filter['store_code'] = store

        male_expr, female_expr = _footfall_exprs(category)

        pipeline = [
            {'$match': match_filter},
            {'$addFields': {
                'date_only': {'$substr': ['$date_time', 0, 10]},
                'male_v':    male_expr,
                'female_v':  female_expr,
            }},
            {'$group': {
                '_id':    {'date': '$date_only', 'store': '$store_code'},
                'male':   {'$sum': '$male_v'},
                'female': {'$sum': '$female_v'},
            }},
            {'$sort': {'_id.date': 1, '_id.store': 1}},
        ]
        for row in collection.aggregate(pipeline):
            m, f = row.get('male', 0), row.get('female', 0)
            writer.writerow([row['_id'].get('date', 'Unknown'), row['_id'].get('store', 'Unknown'), m, f, m + f])

    response = Response(output.getvalue(), mimetype='text/csv')
    store_label = store if store else 'AllStores'
    response.headers['Content-Disposition'] = (
        f'attachment; filename={category.capitalize()}_Export_'
        f'{start_dt.strftime("%Y%m%d")}_{end_dt.strftime("%Y%m%d")}_{store_label}.csv'
    )
    return response

# ─── Heatmap ──────────────────────────────────────────────────────────────────
# heatmap collection camera_no 1 -> base image from nvr_monitoring camera_no 2 (stream_type=main)
# heatmap collection camera_no 2 -> base image from nvr_monitoring camera_no 4 (stream_type=main)
# The "main" stream is captured at 960x1088, matching the resolution the heatmap
# person_bbox_list coordinates were detected at.
HEATMAP_SRC_RESOLUTION = {'w': 960, 'h': 1088}
_HM_TO_NVR_CAMERA = {1: 2, 2: 4}
_HM_CAMERAS = {
    1: {'label': 'Camera 1'},
    2: {'label': 'Camera 2'},
}

def _latest_nvr_main_image(db, nvr_camera_no, store):
    match_filter = {
        'project_name': PROJECT_NAME,
        'camera_no': nvr_camera_no,
        'stream_type': 'main',
    }
    if store:
        match_filter['store_code'] = store
    doc = db['nvr_monitoring'].find_one(match_filter, sort=[('date_time', -1)])
    return doc.get('image_url') if doc else None

@app.route('/api/cultfit/heatmap')
@require_login
def cf_heatmap():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()
    camera_param = request.args.get('camera', '1')
    try:
        hm_camera_no = int(camera_param)
    except ValueError:
        hm_camera_no = 1
    if hm_camera_no not in _HM_CAMERAS:
        hm_camera_no = 1
    nvr_camera_no = _HM_TO_NVR_CAMERA[hm_camera_no]

    db = _get_db()
    if db is None:
        return jsonify({'cameras': [], 'total': 0, 'male': 0, 'female': 0,
                         'child': 0, 'staff': 0, 'docs': 0, 'db_connected': False})

    try:
        collection = db['heatmap']
        collection.create_index(
            [('project_name', 1), ('store_code', 1), ('camera_no', 1), ('date_time', 1)],
            background=True, name='hm_perf_idx'
        )

        match_filter = {
            'project_name': PROJECT_NAME,
            'camera_no': hm_camera_no,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            match_filter['store_code'] = store

        docs = list(collection.find(
            match_filter,
            {'_id': 0, 'camera_no': 1, 'person_bbox_list': 1, 'count': 1}
        ).limit(5000))

        agg = {'docs': 0, 'total': 0, 'male': 0, 'female': 0, 'child': 0, 'staff': 0, 'points': []}
        for doc in docs:
            cnt = doc.get('count', {}) or {}
            bboxes = doc.get('person_bbox_list', {}) or {}

            agg['docs'] += 1
            agg['male']   += int(cnt.get('male',   0))
            agg['female'] += int(cnt.get('female', 0))
            agg['child']  += int(cnt.get('child',  0))
            agg['staff']  += int(cnt.get('staff',  0))
            agg['total']  += (int(cnt.get('male', 0)) + int(cnt.get('female', 0)) +
                              int(cnt.get('child', 0)) + int(cnt.get('staff', 0)))

            for gender, boxes in bboxes.items():
                if not isinstance(boxes, list):
                    continue
                for box in boxes[:20]:
                    if isinstance(box, (list, tuple)) and len(box) == 4:
                        agg['points'].append({
                            'x1': box[0], 'y1': box[1], 'x2': box[2], 'y2': box[3],
                            'g': gender[0] if gender else 'u',
                        })

        points = agg['points']
        if len(points) > 4000:
            import random
            points = random.sample(points, 4000)

        image_url = _latest_nvr_main_image(db, nvr_camera_no, store)

        camera_result = {
            'camera_no':     hm_camera_no,
            'nvr_camera_no': nvr_camera_no,
            'label':         _HM_CAMERAS[hm_camera_no]['label'],
            'image':         image_url,
            'src_w':         HEATMAP_SRC_RESOLUTION['w'],
            'src_h':         HEATMAP_SRC_RESOLUTION['h'],
            'docs':          agg['docs'],
            'total':         agg['total'],
            'male':          agg['male'],
            'female':        agg['female'],
            'child':         agg['child'],
            'staff':         agg['staff'],
            'points':        points,
        }

        return jsonify({
            'cameras':      [camera_result],
            'total':        agg['total'],
            'male':         agg['male'],
            'female':       agg['female'],
            'child':        agg['child'],
            'staff':        agg['staff'],
            'docs':         agg['docs'],
            'db_connected': True,
        })

    except Exception as exc:
        import traceback; traceback.print_exc()
        print(f"[DB] Heatmap query error: {exc}")
        return jsonify({'error': 'Database query failed', 'detail': str(exc)}), 503

# ─── Static / SPA ─────────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    _get_db()  # Test connection at startup
    port = int(os.environ.get('PORT', 20690))
    app.run(host='0.0.0.0', port=port, debug=(os.environ.get('FLASK_ENV') == 'development'))
