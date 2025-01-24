import json

def process_file(filename):
    print(filename)
    with open(filename) as f:
        lines = []
        for line in f:
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith('#'):
                continue
                
            if "'" in stripped:
                indent = len(stripped) - len(stripped.lstrip())
                content = stripped[indent:]
                
                has_comma = content.endswith(',')
                if has_comma:
                    content = content[:-1]
                
                inner = content[1:-1]
                inner = inner.replace('"', "'")
                
                result = ' ' * indent + f'"{inner}"'
                if has_comma:
                    result += ','
                lines.append(result)
            else:
                lines.append(stripped)
        
        return '\n'.join(lines)

def transform_data(data):
    result = []
    for malware_name, queries in data.items():
        for idx, query in enumerate(queries, 1):
            result.append({
                "query": query,
                "tag": "IOA,Lab,Monty",
                "malware_name": f"{malware_name}_{idx}",
                "active": "no"
            })
    return result

def main(input_file, output_file):
    cleaned_content = process_file(input_file)
    print("If you run into issues please run the input data through jsonlint.com and identify the non-compliant json")
    data = json.loads(cleaned_content)
    result = transform_data(data)
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=4)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python script.py input_file output_file")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
