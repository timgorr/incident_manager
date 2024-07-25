from flask import Flask, request, jsonify, g
import sqlite3
from jsonschema import validate, ValidationError
import models
from pymisp_interface import send_to_misp
from stix_interface import create_stix_package

app = Flask(__name__)
app.config.from_object('config.Config')

# JSON schema as defined previously
schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "This document records the details of an incident",
    "title": "Record of a SIEM Incident",
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "report_category": {"type": "string", "enum": ["eu.acdc.attack"]},
        "report_type": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "source_key": {"type": "string", "enum": ["ip"]},
        "source_value": {"type": "string"},
        "confidence_level": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "version": {"type": "integer", "enum": [2]},
        "report_subcategory": {
            "type": "string",
            "enum": ["abuse", "abuse.spam", "compromise", "data", "dos", "dos.dns", "dos.http", "dos.tcp", "dos.udp",
                     "login", "malware", "scan", "other"]
        },
        "ip_protocol_number": {"type": "integer", "minimum": 0, "maximum": 255},
        "ip_version": {"type": "integer", "enum": [4, 6]}
    },
    "required": ["id", "report_category", "timestamp", "source_key", "source_value", "confidence_level", "version",
                 "ip_protocol_number", "ip_version"]
}

@app.route('/api/report', methods=['POST'])
def handle_report():
    data = request.get_json()
    try:
        validate(instance=data, schema=schema)  # Validate data
        models.add_report(data)
        response_misp = send_to_misp(data)
        stix_package = create_stix_package(data)
        # Assume sending to TAXII server is done here
        return (jsonify({"status": "success", "misp_response": str(response_misp), "stix_package": str(stix_package)}),
                200)
    except ValidationError as ve:
        return jsonify({"error": "Invalid data: " + str(ve)}), 400
    except sqlite3.Error as e:
        return jsonify({"error": "Database error: " + str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Unexpected error: " + str(e)}), 500
# for manual input - via curl for example (api endpoint simulation) or "Postman" ?

# Create a Rule: Define a rule in your SIEM system to trigger on specific security events or logs.
# ((Set up the Webhook: Configure the rule to send the event data to your Flask application endpoint.
# The configuration usually involves specifying the URL (e.g., http://your-flask-app/api/siem-report) and the HTTP method (POST).))
#



@app.route('/api/siem-report', methods=['POST'])
def handle_siem_report():
    data = request.get_json()
    try:
        validate(instance=data, schema=schema)  # Validate data
        models.add_report(data)
        response_misp = send_to_misp(data)
        stix_package = create_stix_package(data)
        return jsonify({"status": "success", "misp_response": str(response_misp), "stix_package": str(stix_package)}), 200
    except ValidationError as ve:
        return jsonify({"error": "Invalid data: " + str(ve)}), 400
    except sqlite3.Error as e:
        return jsonify({"error": "Database error: " + str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Unexpected error: " + str(e)}), 500
# automated data input SIEM ( can be integrated in MISP, STIX)



@app.route('/api/assets', methods=['GET', 'POST'])
def assets():
    if request.method == 'POST':
        asset_data = request.get_json()
        return jsonify(models.add_asset(asset_data)), 201
    else:
        return jsonify(models.get_assets())

@app.route('/reports', methods=['GET'])
def view_reports():
    return jsonify(models.get_reports())

if __name__ == '__main__':
    models.init_db()
    app.run(debug=True)
