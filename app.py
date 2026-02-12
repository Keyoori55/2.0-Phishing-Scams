from flask import Flask, render_template, request, jsonify
from logic.detector import analyze_url, analyze_email, analyze_file
import time

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/what-is-phishing')
def what_is_phishing():
    return render_template('what_is_phishing.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Simulate processing time
    time.sleep(1.5)
    result = analyze_url(url)
    return jsonify(result)

@app.route('/api/scan/email', methods=['POST'])
def scan_email():
    data = request.json
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "No email content provided"}), 400
    
    # Simulate processing time
    time.sleep(1.5)
    result = analyze_email(text)
    return jsonify(result)

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    # In a real app we'd handle the file upload, 
    # but based on the JS version it's just analyzing the filename
    file_name = request.json.get('fileName', '')
    if not file_name:
        return jsonify({"error": "No file name provided"}), 400
        
    # Simulate processing time
    time.sleep(1.5)
    result = analyze_file(file_name)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
