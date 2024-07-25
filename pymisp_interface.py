from pymisp import PyMISP, MISPEvent, MISPAttribute

def send_to_misp(misp_url, misp_key, data):
    misp_url = 'https://dein-misp-server-url'
    misp_key = 'dein_auth_schluessel'
    pymisp = PyMISP(misp_url, misp_key, ssl=True)  # Adjust SSL based on your environment (https: ssl = true)

    # Create new event
    event = MISPEvent()
    event.info = data.get('report_type', 'No report type provided')
    event.distribution = 0  # Set as per your MISP configuration
    event.threat_level_id = 2  # Medium by default
    event.analysis = 1  # Ongoing analysis

    # Create and add IP attribute
    if 'source_ip' in data:
        ip_attribute = MISPAttribute()
        ip_attribute.category = 'Network activity'
        ip_attribute.type = 'ip-dst'
        ip_attribute.value = data['source_ip']
        event.add_attribute(ip_attribute)

    # Example of adding another attribute, ensuring 'value' is correctly filled
    if 'domain' in data:
        domain_attribute = MISPAttribute()
        domain_attribute.category = 'Network activity'
        domain_attribute.type = 'domain'
        domain_attribute.value = data['domain']
        event.add_attribute(domain_attribute)

    # Send the event to MISP
    try:
        response = pymisp.add_event(event)
        pymisp.publish(response)
        return {'status': 'success', 'event_id': response.id}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
