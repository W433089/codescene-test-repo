def _helper_processor(type_name, value):
    """Helper function to remove duplication."""
    print(f"Processing Type {type_name}")
    print(f"Data value: {value}")
    print("Processing complete")

def process_data(data):
    if 'type' in data:
        _helper_processor(data['type'], data['value'])

def log_data(data):
    if 'type' in data:
        _helper_processor(data['type'], data['value'])