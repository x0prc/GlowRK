import os
import sys
import json
import subprocess
from flask import Flask, request, jsonify
from analysis.memory_analysis import analyze_memory_dump
from analysis.detection import (
    detect_idt_modifications,
    detect_ssdt_modifications,
    detect_iat_modifications,
    check_file_integrity
)

app = Flask(__name__)


UPLOAD_FOLDER = 'data/raw_dumps'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'memoryDump' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['memoryDump']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    
    results = analyze_memory_dump(file_path)

    return jsonify(results), 200

@app.route('/results', methods=['GET'])
def get_results():
  
    return jsonify({"message": "Results will be displayed here."}), 200

def analyze_memory_dump(dump_path):
   
    memory_data = subprocess.run(
        ['volatility', '-f', dump_path, '--profile=Win7SP1x64', 'pslist'],
        capture_output=True,
        text=True
    ).stdout

    results = {
        "memory_analysis": memory_data,
        "idt_check": detect_idt_modifications(memory_data),
        "ssdt_check": detect_ssdt_modifications(memory_data),
        "iat_check": detect_iat_modifications(memory_data),
        "integrity_check": check_file_integrity(dump_path)
    }

    return results

if __name__ == '__main__':
    app.run(debug=True, port=5000)
