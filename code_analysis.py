def process_data(data):
    # A simple code smell: duplicated block
    if 'type' in data and data['type'] == 'A':
        print("Processing Type A")
        print(f"Data value: {data['value']}")
        print("Processing complete")

    if 'type' in data and data['type'] == 'B':
        print("Processing Type B")
        print(f"Data value: {data['value']}")
        print("Processing complete")

# Another code smell: duplicated block
def log_data(data):
    if 'type' in data and data['type'] == 'A':
        print("Processing Type A")
        print(f"Data value: {data['value']}")
        print("Processing complete")

    if 'type' in data and data['type'] == 'B':
        print("Processing Type B")
        print(f"Data value: {data['value']}")
        print("Processing complete")