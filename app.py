from flask import Flask, jsonify, request, session, send_from_directory, Response
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import os, csv, io, time, json, collections
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
    'ALLOWED_ORIGINS', 'http://localhost:21699,http://127.0.0.1:21699'
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

# ─── GCS signed URLs ───────────────────────────────────────────────────────────
_gcs_client = None
_GCS_PREFIX = "https://storage.googleapis.com/"

def _init_gcs():
    global _gcs_client
    key_path = os.environ.get('GCS_KEY_PATH') or os.environ.get('GCS_KEY') or \
        os.path.join(os.path.dirname(__file__), 'gcs-key.json')
    if os.path.exists(key_path):
        try:
            from google.cloud import storage
            _gcs_client = storage.Client.from_service_account_json(key_path)
            print(f"[GCS] client initialised from {key_path}", flush=True)
        except Exception as e:
            print(f"[GCS] ERROR initialising client: {e}", flush=True)
    else:
        print(f"[GCS] key file not found at {key_path}", flush=True)

_init_gcs()

def signed_url(raw_url: str, expires_minutes: int = 15) -> str:
    if not raw_url or not raw_url.startswith(_GCS_PREFIX) or _gcs_client is None:
        return raw_url
    path = raw_url[len(_GCS_PREFIX):]
    bucket_name, _, blob_name = path.partition("/")
    bucket = _gcs_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    try:
        return blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=expires_minutes),
            method="GET",
        )
    except Exception as e:
        print(f"[GCS] ERROR signing URL: {e}", flush=True)
        return raw_url

PROJECT_NAME = 'Cultfit'

# ─── Auth ─────────────────────────────────────────────────────────────────────
# Password hash is for: TarsyerxCult.fit
_TARSYER_PASSWORD_HASH = '$2b$12$05O2Is25xTkix2429U8s/OklA/is/xfqEBjuffFx5UjPqrgbcmr8q'

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
_CF_STORES_FALLBACK = ['Cultfit-Mantri-Mall', 'Cultfit-HSR']

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

# ─── Store opening/closing hours ───────────────────────────────────────────────
# store_hours.json: { "<store_code>": { "open": "HH:MM", "close": "HH:MM" } }
_STORE_HOURS_FILE = os.path.join(os.path.dirname(__file__), 'store_hours.json')

def _load_store_hours():
    try:
        with open(_STORE_HOURS_FILE, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _hours_bracket(store):
    """Returns (open_str, close_str, source) for a store code, or ('all' -> union
    of earliest open / latest close across every store in store_hours.json)."""
    hours = _load_store_hours()
    if not hours:
        return None
    if store and store in hours:
        entry = hours[store]
        return entry.get('open'), entry.get('close'), 'store'

    # No specific store selected (or store not in file) -> widest bracket:
    # earliest open time and latest close time across all known stores.
    opens  = [e.get('open')  for e in hours.values() if e.get('open')]
    closes = [e.get('close') for e in hours.values() if e.get('close')]
    if not opens or not closes:
        return None
    return min(opens), max(closes), 'union'

@app.route('/api/cultfit/store-hours')
@require_login
def cf_store_hours():
    store = request.args.get('store', '')
    store = '' if store in ('all', 'All', '') else store
    bracket = _hours_bracket(store)
    if not bracket:
        return jsonify({'available': False})
    open_str, close_str, source = bracket
    return jsonify({'available': True, 'open': open_str, 'close': close_str, 'source': source})

def _hour_set_for_bracket(open_str, close_str):
    """Expands an HH:MM-HH:MM bracket into the set of included hour buckets (0-23),
    rounding a partial closing hour up so it's still shown. Handles overnight wrap
    (e.g. open 22:00, close 02:00)."""
    try:
        open_h  = int(open_str.split(':')[0])
        close_h, close_m = close_str.split(':')
        close_h = int(close_h) + (1 if int(close_m) > 0 else 0)
    except Exception:
        return None
    if open_h == close_h:
        return None  # can't determine a meaningful bracket
    if open_h < close_h:
        return set(range(open_h, min(close_h, 24)))
    return set(range(open_h, 24)) | set(range(0, close_h % 24))

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

# ─── Footfall (Male / Female — camera_no 1) ───────────────────────────────────
# ─── Passerby (Male / Female — camera_no 2, count+opp_count, staff->female, child->male)
def _footfall_exprs(category):
    if category == 'footfall':
        # male = count_female only ; female = count_male + count_child
        male_expr = {'$ifNull': ['$count_female', 0]}
        female_expr = {'$add': [
            {'$ifNull': ['$count_male', 0]},
            {'$ifNull': ['$count_child', 0]},
        ]}
    else:
        # passerby: male = count_male + opp_count_male (count_child excluded)
        #           female = count_female + opp_count_female + count_staff + opp_count_staff
        male_expr = {'$add': [
            {'$ifNull': ['$count_male', 0]},
            {'$ifNull': ['$opp_count_male', 0]},
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

        # Restrict hourly rows to the selected store's opening/closing bracket
        # (or the widest open/close span across all stores when 'All Stores' is
        # selected). Daily/by-store totals are left unfiltered.
        bracket = _hours_bracket(store)
        if bracket:
            allowed_hours = _hour_set_for_bracket(bracket[0], bracket[1])
            if allowed_hours is not None:
                hourly = [r for r in hourly if int(r['hour'][:2]) in allowed_hours]

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

# ─── Camera ROI (Region of Interest) config ───────────────────────────────────
# roi_config.json: { "<store_code>": { "<camera_no>": [ {"x":.., "y":..}, ... ] } }
# When a (store_code, camera_no) pair has a polygon here, heatmap detections
# whose bbox center falls outside it are dropped entirely from both the point
# cloud used to draw the density overlay and the male/female/child/staff
# totals returned to the frontend. Pairs with no entry behave exactly as
# before (unfiltered) — this is additive, not a redesign of the pipeline.
_ROI_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'roi_config.json')

def _load_roi_config():
    try:
        with open(_ROI_CONFIG_FILE, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _get_roi_polygon(store, camera_no):
    store_cfg = _load_roi_config().get(store)
    if not store_cfg:
        return None
    poly = store_cfg.get(str(camera_no))
    if not poly:
        return None
    return [(p['x'], p['y']) for p in poly]

def _point_in_polygon(x, y, poly):
    """Ray-casting point-in-polygon test; poly is a list of (x, y) vertices."""
    inside = False
    x1, y1 = poly[-1]
    for x2, y2 in poly:
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            inside = not inside
        x1, y1 = x2, y2
    return inside

# ─── Heatmap ──────────────────────────────────────────────────────────────────
# Cameras are discovered dynamically from whatever camera_no values are present
# in the heatmap collection (no fixed camera list, no cap). For each camera_no
# found, the latest matching image with the SAME camera_no is looked up in
# nvr_monitoring. A camera is only included in the response if both a heatmap
# doc and a matching nvr_monitoring image were found.
#
# Cultfit-HSR's gate/heatmap capture now runs off the substream (960x576)
# instead of the main stream (1920x1080), so its background snapshot must come
# from stream_type='sub' — every other store still uses 'main'. The frontend
# doesn't assume any fixed resolution; it plots bbox coordinates unscaled
# against the actual displayed image's native size, so as long as the image
# fetched here matches the resolution the bboxes for that store were detected
# at, there's nothing else to keep in sync.
HEATMAP_SUBSTREAM_STORES = {'Cultfit-HSR'}

def _latest_nvr_image(db, camera_no, store):
    stream_type = 'sub' if store in HEATMAP_SUBSTREAM_STORES else 'main'
    match_filter = {
        'project_name': PROJECT_NAME,
        'camera_no': camera_no,
        'stream_type': stream_type,
    }
    if store:
        match_filter['store_code'] = store
    doc = db['nvr_monitoring'].find_one(match_filter, sort=[('date_time', -1)])
    return signed_url(doc.get('image_url')) if doc else None

@app.route('/api/cultfit/heatmap')
@require_login
def cf_heatmap():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()

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

        base_filter = {
            'project_name': PROJECT_NAME,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            base_filter['store_code'] = store

        camera_nos = sorted(collection.distinct('camera_no', base_filter))

        cameras_result = []
        totals = {'docs': 0, 'total': 0, 'male': 0, 'female': 0, 'child': 0, 'staff': 0}

        for camera_no in camera_nos:
            match_filter = dict(base_filter, camera_no=camera_no)
            roi_poly = _get_roi_polygon(store, camera_no)

            docs = list(collection.find(
                match_filter,
                {'_id': 0, 'camera_no': 1, 'person_bbox_list': 1, 'count': 1}
            ).limit(5000))
            if not docs:
                continue

            image_url = _latest_nvr_image(db, camera_no, store)
            if not image_url:
                continue

            agg = {'docs': 0, 'total': 0, 'male': 0, 'female': 0, 'child': 0, 'staff': 0, 'points': []}
            for doc in docs:
                bboxes = doc.get('person_bbox_list', {}) or {}
                agg['docs'] += 1

                if roi_poly is not None:
                    # The doc's `count` dict has no per-box position, so an
                    # ROI-scoped total can't be read from it — it has to be
                    # derived from boxes actually inside the polygon. Every
                    # category (including staff) is counted here for
                    # analytics correctness, even though staff boxes are
                    # never added to the drawn point cloud below.
                    doc_male = doc_female = doc_child = doc_staff = 0
                    for gender in ('male', 'female', 'child', 'staff'):
                        boxes = bboxes.get(gender)
                        if not isinstance(boxes, list):
                            continue
                        kept_points = 0
                        for box in boxes:
                            if not (isinstance(box, (list, tuple)) and len(box) == 4):
                                continue
                            cx = (box[0] + box[2]) / 2.0
                            cy = (box[1] + box[3]) / 2.0
                            if not _point_in_polygon(cx, cy, roi_poly):
                                continue
                            if gender == 'male':     doc_male += 1
                            elif gender == 'female': doc_female += 1
                            elif gender == 'child':  doc_child += 1
                            else:                    doc_staff += 1
                            if gender != 'staff' and kept_points < 20:
                                agg['points'].append({
                                    'x1': box[0], 'y1': box[1], 'x2': box[2], 'y2': box[3],
                                    'g': gender[0],
                                })
                                kept_points += 1
                else:
                    cnt = doc.get('count', {}) or {}
                    doc_male   = int(cnt.get('male',   0))
                    doc_female = int(cnt.get('female', 0))
                    doc_child  = int(cnt.get('child',  0))
                    doc_staff  = int(cnt.get('staff',  0))

                    for gender, boxes in bboxes.items():
                        if gender == 'staff' or not isinstance(boxes, list):
                            continue
                        for box in boxes[:20]:
                            if isinstance(box, (list, tuple)) and len(box) == 4:
                                agg['points'].append({
                                    'x1': box[0], 'y1': box[1], 'x2': box[2], 'y2': box[3],
                                    'g': gender[0] if gender else 'u',
                                })

                agg['male']   += doc_male
                agg['female'] += doc_female
                agg['child']  += doc_child
                agg['staff']  += doc_staff
                agg['total']  += doc_male + doc_female + doc_child + doc_staff

            points = agg['points']
            if len(points) > 4000:
                import random
                points = random.sample(points, 4000)

            cameras_result.append({
                'camera_no':     camera_no,
                'label':         f'Camera {camera_no}',
                'image':         image_url,
                'docs':          agg['docs'],
                'total':         agg['total'],
                'male':          agg['male'],
                'female':        agg['female'],
                'child':         agg['child'],
                'staff':         agg['staff'],
                'points':        points,
            })

            totals['docs']   += agg['docs']
            totals['total']  += agg['total']
            totals['male']   += agg['male']
            totals['female'] += agg['female']
            totals['child']  += agg['child']
            totals['staff']  += agg['staff']

        return jsonify({
            'cameras':      cameras_result,
            'total':        totals['total'],
            'male':         totals['male'],
            'female':       totals['female'],
            'child':        totals['child'],
            'staff':        totals['staff'],
            'docs':         totals['docs'],
            'db_connected': True,
        })

    except Exception as exc:
        import traceback; traceback.print_exc()
        print(f"[DB] Heatmap query error: {exc}")
        return jsonify({'error': 'Database query failed', 'detail': str(exc)}), 503

# ─── Shopper Flow (reid collection — zone-based 2D floor-plan map) ────────────
# reid docs carry a `store_location` field (e.g. "Zone_5") identifying which
# physical zone that detection belongs to — this is store-wide zone
# granularity, finer than camera_no, and is what floor plan polygons in
# static/floor_plans/<store_code>.svg are keyed against via their
# `data-zone` attribute. `gender` maps gender -> list of person IDs present
# in that doc; `person_bbox_list` maps person ID -> that person's boxes seen
# within the doc. Children are folded into the 'male' bucket (same rule used
# for trail coloring elsewhere in this app); staff are always skipped. A
# person appearance only counts if it has >= 2 boxes in that doc (noise
# filter), matching the point-count filter already used elsewhere.
#
# Journeys: per person, the zones they were seen in are ordered by
# date_time and consecutive duplicate zones are collapsed. Camera coverage
# is sparse enough that a person's raw sequence can "skip" straight from one
# zone to a physically distant one (e.g. Zone_1 -> Zone_10) with no detection
# in the zones between — drawn as a single arrow, that reads as a long jump
# across the whole store instead of a walking path. Before counting
# transitions/journeys, each raw hop is checked against the store's zone
# adjacency graph (built from actual polygon proximity in
# static/floor_plans/<store_code>.json — see _build_zone_adjacency); any
# non-adjacent hop is bridged via the shortest path of real adjacent zones
# between the two, so both `transitions` and `top_journeys` only ever
# contain physically continuous, nearby-zone-to-nearby-zone hops. "Entry"
# (the store's single physical entrance/exit) is prepended as the first
# waypoint; which zone(s) it's adjacent to is derived from the entrance's
# pixel position vs. each zone's polygon (same proximity rule used for
# zone-to-zone adjacency) rather than by matching section names, since an
# entrance doesn't always sit inside a single named section (e.g. Cultfit-
# Mantri-Mall's entrance sits on the boundary between two sections and is
# adjacent to a zone in each). Any `store_location` value seen in the raw
# reid data that isn't one of the zones defined in the store's floor plan
# JSON is dropped entirely — not guessed at, not partially shown.
SHOPPERFLOW_MAX_JOURNEYS = 10
ZONE_ADJACENCY_GAP_PX = 60   # max polygon edge-to-edge gap (px) to count two zones as neighbors

_FLOOR_PLAN_DIR = os.path.join(os.path.dirname(__file__), 'static', 'floor_plans')
_zone_geometry_cache = {}

def _load_zone_geometry(store):
    """Zone bounding boxes + the entrance's pixel position, read from
    static/floor_plans/<store>.json. Returns None if that file doesn't exist."""
    if store in _zone_geometry_cache:
        return _zone_geometry_cache[store]

    geometry = None
    path = os.path.join(_FLOOR_PLAN_DIR, f'{store}.json')
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            fp = data.get('floor_plan', {})
            entrance_position = (fp.get('entrance') or {}).get('position')

            zones = {}
            for section in fp.get('sections', []):
                for z in section.get('zones', []):
                    poly = z.get('polygon') or []
                    if not poly or not z.get('zone_id'):
                        continue
                    xs = [p[0] for p in poly]
                    ys = [p[1] for p in poly]
                    zones[z['zone_id']] = {
                        'x0': min(xs), 'x1': max(xs),
                        'y0': min(ys), 'y1': max(ys),
                    }

            geometry = {'zones': zones, 'entrance_position': entrance_position}
        except Exception as exc:
            print(f"[FloorPlan] Failed to load geometry for {store}: {exc}")
            geometry = None

    _zone_geometry_cache[store] = geometry
    return geometry

def _rect_gap(a, b):
    """Edge-to-edge gap between two axis-aligned rects; 0 (or negative) if they overlap/touch."""
    dx = max(a['x0'] - b['x1'], b['x0'] - a['x1'], 0)
    dy = max(a['y0'] - b['y1'], b['y0'] - a['y1'], 0)
    if dx > 0 and dy > 0:
        return (dx ** 2 + dy ** 2) ** 0.5
    return max(dx, dy)

def _build_zone_adjacency(store):
    """zone_id -> set(neighboring zone_ids), including 'Entry', derived from real
    polygon proximity (not a hand-picked sequence) so branching at multi-zone
    sections falls out naturally. Returns None if no floor plan geometry exists
    for this store."""
    geometry = _load_zone_geometry(store)
    if not geometry:
        return None

    zones = geometry['zones']
    adjacency = {zid: set() for zid in zones}
    adjacency['Entry'] = set()

    entrance_position = geometry.get('entrance_position')
    if entrance_position:
        entrance_pt = {
            'x0': entrance_position['x'], 'x1': entrance_position['x'],
            'y0': entrance_position['y'], 'y1': entrance_position['y'],
        }
        for zid, rect in zones.items():
            if _rect_gap(entrance_pt, rect) <= ZONE_ADJACENCY_GAP_PX:
                adjacency['Entry'].add(zid)
                adjacency[zid].add('Entry')

    zids = list(zones.keys())
    for i in range(len(zids)):
        for j in range(i + 1, len(zids)):
            a, b = zids[i], zids[j]
            if _rect_gap(zones[a], zones[b]) <= ZONE_ADJACENCY_GAP_PX:
                adjacency[a].add(b)
                adjacency[b].add(a)
    return adjacency

def _shortest_zone_path(adjacency, start, end):
    """BFS shortest path between two nodes of the adjacency graph, inclusive of
    both ends. Returns None if unreachable."""
    if start == end:
        return [start]
    visited = {start}
    queue = collections.deque([[start]])
    while queue:
        path = queue.popleft()
        node = path[-1]
        for neighbor in sorted(adjacency.get(node, ())):
            if neighbor == end:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])
    return None

def _stitch_zone_path(adjacency, raw_path):
    """Bridge any non-adjacent hop in raw_path through real intermediate zones
    via the shortest adjacency path, so every hop in the result is a
    physically continuous, nearby-zone-to-nearby-zone step."""
    if not adjacency:
        return raw_path
    stitched = [raw_path[0]]
    for zone in raw_path[1:]:
        prev = stitched[-1]
        if zone in adjacency.get(prev, ()):
            stitched.append(zone)
        else:
            bridge = _shortest_zone_path(adjacency, prev, zone)
            if bridge:
                stitched.extend(bridge[1:])
            else:
                stitched.append(zone)
    return stitched

@app.route('/api/cultfit/shopper-flow')
@require_login
def cf_shopper_flow():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()

    db = _get_db()
    if db is None:
        return jsonify({'zone_traffic': {}, 'transitions': [], 'top_journeys': [],
                         'total_journeys': 0, 'total_unique': 0, 'db_connected': False})

    try:
        collection = db['reid']
        collection.create_index(
            [('project_name', 1), ('store_code', 1), ('date_time', 1)],
            background=True, name='sf_perf_idx'
        )

        match_filter = {
            'project_name': PROJECT_NAME,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            match_filter['store_code'] = store

        # Zones not defined in this store's floor plan (e.g. a camera/section
        # not yet mapped) are dropped entirely, not guessed at or partially
        # shown — known_zones stays None (no filtering) if there's no floor
        # plan for this store at all.
        geometry = _load_zone_geometry(store) if store else None
        known_zones = set(geometry['zones'].keys()) if geometry else None

        # No server-side sort here — each person's timeline is re-sorted by
        # date_time locally below, so an (expensive, potentially unindexed)
        # whole-collection sort on the DB side isn't needed.
        docs = collection.find(
            match_filter,
            {'_id': 0, 'date_time': 1, 'store_location': 1, 'gender': 1, 'person_bbox_list': 1}
        )

        # (person_id, zone, date_time) appearances, noise-filtered
        person_zone_counts = {}          # zone -> set(person_id)
        person_timeline     = {}          # person_id -> [(date_time, zone), ...]

        for doc in docs:
            zone = doc.get('store_location')
            if not zone:
                continue
            if known_zones is not None and zone not in known_zones:
                continue
            dt_str = doc.get('date_time') or ''
            gender = doc.get('gender') or {}
            bboxes = doc.get('person_bbox_list') or {}
            if not isinstance(bboxes, dict):
                continue

            person_ids = set()
            for key in ('male', 'child', 'female'):
                person_ids.update(str(p) for p in (gender.get(key) or []))

            for pid in person_ids:
                boxes = bboxes.get(pid)
                if not isinstance(boxes, list) or len(boxes) < 2:
                    continue
                person_zone_counts.setdefault(zone, set()).add(pid)
                if dt_str:
                    person_timeline.setdefault(pid, []).append((dt_str, zone))

        zone_traffic = {zone: len(pids) for zone, pids in person_zone_counts.items()}
        total_unique = len(person_timeline)

        # Build per-person journeys (dedup consecutive zones, prepend Entry,
        # then bridge non-adjacent hops through real intermediate zones)
        adjacency = _build_zone_adjacency(store) if store else None
        transition_counts = {}
        journey_counts = {}

        for pid, timeline in person_timeline.items():
            timeline.sort(key=lambda x: x[0])
            raw_path = ['Entry']
            for _, zone in timeline:
                if raw_path[-1] != zone:
                    raw_path.append(zone)
            if len(raw_path) < 2:
                continue
            path = _stitch_zone_path(adjacency, raw_path)
            for i in range(len(path) - 1):
                pair = (path[i], path[i + 1])
                transition_counts[pair] = transition_counts.get(pair, 0) + 1
            journey_str = ' → '.join(path)
            journey_counts[journey_str] = journey_counts.get(journey_str, 0) + 1

        formatted_transitions = [
            {'from': f_zone, 'to': t_zone, 'count': cnt}
            for (f_zone, t_zone), cnt in sorted(transition_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        # `count` is the number of tracked individuals whose normalized path is
        # exactly this string; `share` is that count as a fraction of ALL
        # multi-zone journeys in the period (not just the top N shown here), so
        # the list reads as a distribution rather than raw re-ID track counts.
        total_journeys = sum(journey_counts.values())

        top_journeys = [
            {
                'journey': journey,
                'count':   cnt,
                'share':   round(cnt / total_journeys, 4) if total_journeys else 0,
            }
            for journey, cnt in sorted(journey_counts.items(), key=lambda x: x[1], reverse=True)[:SHOPPERFLOW_MAX_JOURNEYS]
        ]

        return jsonify({
            'zone_traffic':    zone_traffic,
            'transitions':     formatted_transitions,
            'top_journeys':    top_journeys,
            'total_journeys':  total_journeys,
            'total_unique':    total_unique,
            'db_connected':    True,
        })

    except Exception as exc:
        import traceback; traceback.print_exc()
        print(f"[DB] Shopper flow query error: {exc}")
        return jsonify({'error': 'Database query failed', 'detail': str(exc)}), 503

# ─── Gate Activity (gate_activity collection — daily open/close snapshots) ────
# Each open/close event can be logged by more than one camera (camera_no 1/2)
# at the same date_time, so events are bucketed by the collection's own
# `type` field ('morning'/'evening') rather than by time-of-day — a day with
# only an 'evening' doc (e.g. a delayed one-off close check) must not be
# misread as that store's morning open.
@app.route('/api/cultfit/gate-activity')
@require_login
def cf_gate_activity():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()

    db = _get_db()
    if db is None:
        return jsonify({'rows': [], 'db_connected': False})

    try:
        collection = db['gate_activity']
        match_filter = {
            'project_name': PROJECT_NAME,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            match_filter['store_code'] = store

        docs = collection.find(
            match_filter,
            {'_id': 0, 'store_code': 1, 'date_time': 1, 'image_url': 1,
             'type': 1, 'gate_status': 1, 'camera_no': 1}
        ).sort([('date_time', 1), ('camera_no', 1)])

        # (store, date, type) -> chosen event doc; camera_no 1 wins if a type
        # has more than one camera's snapshot for the same event.
        events = {}
        for doc in docs:
            date_time = doc.get('date_time', '')
            if len(date_time) < 19:
                continue
            ev_type = doc.get('type')
            if ev_type not in ('morning', 'evening'):
                continue
            key = (doc.get('store_code', 'Unknown'), date_time[:10], ev_type)
            if key in events and events[key]['camera_no'] == 1:
                continue
            events[key] = {
                'time':       date_time[11:19],
                'image':      signed_url(doc.get('image_url')),
                'status_lbl': doc.get('gate_status') or ('open' if ev_type == 'morning' else 'close'),
                'camera_no':  doc.get('camera_no'),
            }

        rows_by_day = {}
        for (store_code, date_only, ev_type), ev in events.items():
            rows_by_day.setdefault((store_code, date_only), {})[ev_type] = ev

        rows = []
        for (store_code, date_only), by_type in rows_by_day.items():
            morning_ev = by_type.get('morning')
            evening_ev = by_type.get('evening')

            rows.append({
                'date': date_only,
                'store': store_code,
                'morning': {
                    'time':  morning_ev['time'],
                    'image': morning_ev['image'],
                    'label': morning_ev['status_lbl'],
                } if morning_ev else None,
                'evening': {
                    'time':  evening_ev['time'],
                    'image': evening_ev['image'],
                    'label': evening_ev['status_lbl'],
                } if evening_ev else None,
            })

        rows.sort(key=lambda r: (r['date'], r['store']), reverse=True)

        return jsonify({'rows': rows, 'db_connected': True})

    except Exception as exc:
        print(f"[DB] Gate activity query error: {exc}")
        return jsonify({'error': 'Database query failed', 'detail': str(exc)}), 503

# ─── Staff Presence (footfall collection — camera_no 3) ──────────────────────
# camera_no 3 points at the staff area; it logs one hourly snapshot whose
# `count_male` is the number of staff seen that hour (the other count_* /
# opp_count_* fields are unused on this camera). Presented as a date x hour
# grid: one row per store/day, one column per hour that appears anywhere in
# the range, cell = staff count for that hour.
@app.route('/api/cultfit/staff-presence')
@require_login
def cf_staff_presence():
    start_dt, end_dt, end_dt_inclusive, store = _parse_range()

    db = _get_db()
    if db is None:
        return jsonify({'hours': [], 'rows': [], 'db_connected': False})

    try:
        collection = db['footfall']
        match_filter = {
            'project_name': PROJECT_NAME,
            'camera_no': 3,
            'date_time': {
                '$gte': start_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '$lt':  end_dt_inclusive.strftime('%Y-%m-%d %H:%M:%S'),
            }
        }
        if store:
            match_filter['store_code'] = store

        pipeline = [
            {'$match': match_filter},
            {'$group': {
                '_id': {
                    'date': {'$substr': ['$date_time', 0, 10]},
                    'hour': {'$substr': ['$date_time', 11, 2]},
                    'store': '$store_code',
                },
                'staff': {'$sum': {'$ifNull': ['$count_male', 0]}},
            }},
        ]

        grid = {}                 # (store, date) -> {hour_label: staff}
        hours_seen = set()
        for r in collection.aggregate(pipeline):
            key = (r['_id']['store'], r['_id']['date'])
            hour_label = f"{r['_id']['hour']}:00"
            hours_seen.add(hour_label)
            grid.setdefault(key, {})[hour_label] = r['staff']

        hours = sorted(hours_seen)
        rows = []
        for (store_code, date_only), by_hour in grid.items():
            rows.append({
                'date':    date_only,
                'store':   store_code,
                'by_hour': by_hour,
                'total':   sum(by_hour.values()),
            })
        rows.sort(key=lambda r: (r['date'], r['store']), reverse=True)

        return jsonify({'hours': hours, 'rows': rows, 'db_connected': True})

    except Exception as exc:
        print(f"[DB] Staff presence query error: {exc}")
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
    port = int(os.environ.get('PORT', 21699))
    app.run(host='0.0.0.0', port=port, debug=(os.environ.get('FLASK_ENV') == 'development'))
