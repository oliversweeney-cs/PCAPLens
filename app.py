import json
import os
import uuid
from flask import Flask, render_template, request, jsonify, Response, abort
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from analysis import run_analysis
from analysis.ioc_export import build_ioc_bundle, to_csv_string

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key')

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Stores {result_id: {'results': dict, 'filename': str}}
results_store = {}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _get_stored(result_id):
    """Return (results, filename) for a result_id or abort 404."""
    entry = results_store.get(result_id)
    if not entry:
        abort(404)
    return entry['results'], entry['filename']


@app.template_filter('format_bytes')
def format_bytes(value):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} TB'


@app.template_filter('format_duration')
def format_duration(seconds):
    seconds = float(seconds)
    if seconds < 60:
        return f'{seconds:.2f}s'
    elif seconds < 3600:
        return f'{int(seconds // 60)}m {int(seconds % 60)}s'
    return f'{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m'


@app.template_filter('format_rel_time')
def format_rel_time(seconds):
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return '—'
    if seconds < 60:
        return f'{seconds:.3f}s'
    return f'{int(seconds // 60)}m {seconds % 60:.1f}s'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyse', methods=['POST'])
def analyse():
    if 'pcap' not in request.files:
        return render_template('index.html', error='No file selected.')

    f = request.files['pcap']
    if not f.filename:
        return render_template('index.html', error='No file selected.')

    if not allowed_file(f.filename):
        return render_template('index.html', error='Only .pcap and .pcapng files are accepted.')

    filename = secure_filename(f.filename)
    filepath = os.path.join(UPLOAD_DIR, f'{uuid.uuid4().hex}_{filename}')
    f.save(filepath)

    try:
        results = run_analysis(filepath)
    except Exception as e:
        return render_template('index.html', error=f'Analysis failed: {e}')
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

    result_id = str(uuid.uuid4())
    results_store[result_id] = {'results': results, 'filename': filename}
    return render_template('results.html', results=results, result_id=result_id, filename=filename)


@app.route('/export/json/<result_id>')
def export_json(result_id):
    results, filename = _get_stored(result_id)
    response = jsonify(results)
    response.headers['Content-Disposition'] = 'attachment; filename=pcaplens_report.json'
    return response


@app.route('/export/html/<result_id>')
def export_html(result_id):
    results, filename = _get_stored(result_id)
    html = render_template('export_report.html', results=results, filename=filename)
    return Response(
        html,
        mimetype='text/html',
        headers={'Content-Disposition': 'attachment; filename=pcaplens_report.html'},
    )


@app.route('/export/iocs/json/<result_id>')
def export_iocs_json(result_id):
    results, filename = _get_stored(result_id)
    bundle = build_ioc_bundle(results, source_file=filename)
    response = jsonify(bundle)
    response.headers['Content-Disposition'] = 'attachment; filename=pcaplens_iocs.json'
    return response


@app.route('/export/iocs/csv/<result_id>')
def export_iocs_csv(result_id):
    results, filename = _get_stored(result_id)
    bundle = build_ioc_bundle(results, source_file=filename)
    csv_data = to_csv_string(bundle)
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=pcaplens_iocs.csv'},
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8889, debug=os.getenv('FLASK_ENV') == 'development')
