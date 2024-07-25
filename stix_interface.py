from stix2 import Indicator, Bundle

def create_stix_package(data):
    indicator = Indicator(pattern=f"[file:hashes.'SHA-256' = '{data['hash']}']", pattern_type="stix",
                          valid_from="2020-01-01T12:00:00Z")
    bundle = Bundle(objects=[indicator])
    return bundle
