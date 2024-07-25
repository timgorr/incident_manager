import sqlite3
from flask import g, current_app

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
    return g.db

def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

def add_asset(data):
    db = get_db()
    db.execute('INSERT INTO assets (type, description) VALUES (?, ?)', (data['type'], data['description']))
    db.commit()
    return {"status": "success", "message": "Asset added"}

def add_report(data):
    db = get_db()
    db.execute('''
        INSERT INTO reports (id, report_category, report_type, timestamp, source_key, source_value, 
        confidence_level, version, report_subcategory, ip_protocol_number, ip_version) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (data['id'], data['report_category'], data['report_type'], data['timestamp'], data['source_key'],
        data['source_value'], data['confidence_level'], data['version'], data['report_subcategory'],
        data['ip_protocol_number'], data['ip_version']))
    db.commit()

def get_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM reports')
    reports = cursor.fetchall()
    return {"reports": [dict(zip([column[0] for column in cursor.description], row)) for row in reports]}
def get_assets():
    db = get_db()
    assets = db.execute('SELECT * FROM assets').fetchall()
    return {"assets": assets}
