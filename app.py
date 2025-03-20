from flask import Flask, request, jsonify
from url_checker import analyze_url, is_encoded_url, decode_url
from ml_model import predict_phishing
from document_scanner import scan_document
import os

app = Flask(__name__)

@app.route('/api/check-url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Check if URL is encoded
    if is_encoded_url(url):
        decoded_url = decode_url(url)
        is_encoded = True
    else:
        decoded_url = url
        is_encoded = False
    
    # Analyze URL
    analysis_result = analyze_url(decoded_url)
    
    # Get ML prediction
    ml_prediction = predict_phishing(decoded_url)
    
    result = {
        'original_url': url,
        'decoded_url': decoded_url if is_encoded else None,
        'is_encoded': is_encoded,
        'is_malicious': analysis_result['is_malicious'] or ml_prediction['is_phishing'],
        'confidence': ml_prediction['confidence'],
        'analysis': analysis_result,
        'recommendation': 'block' if (analysis_result['is_malicious'] or ml_prediction['is_phishing']) else 'safe'
    }
    
    return jsonify(result)

@app.route('/api/scan-document', methods=['POST'])
def scan_document_endpoint():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    # Check file type
    allowed_extensions = {'pdf', 'doc', 'docx'}
    if not file.filename.split('.')[-1].lower() in allowed_extensions:
        return jsonify({'error': 'File type not supported'}), 400
    
    # Save temporarily
    file_path = os.path.join('temp', file.filename)
    file.save(file_path)
    
    # Scan document
    scan_results = scan_document(file_path)
    
    # Delete temporary file
    os.remove(file_path)
    
    return jsonify(scan_results)

@app.route('/api/scan-qr', methods=['POST'])
def scan_qr_endpoint():
    if 'image' not in request.files: 
        return jsonify({'error': 'No QR image provided'}), 400
        
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No image selected'}), 400
    
    # Save temporarily
    file_path = os.path.join('temp', file.filename)
    file.save(file_path)
    
    # Extract URL from QR code and analyze it
    from document_scanner import extract_url_from_qr
    url = extract_url_from_qr(file_path)
    
    if not url:
        return jsonify({'error': 'No URL found in QR code'}), 400
    
    # Analyze extracted URL
    analysis_result = analyze_url(url)
    ml_prediction = predict_phishing(url)
    
    # Delete temporary file
    os.remove(file_path)
    
    result = {
        'url': url,
        'is_malicious': analysis_result['is_malicious'] or ml_prediction['is_phishing'],
        'confidence': ml_prediction['confidence'],
        'analysis': analysis_result,
        'recommendation': 'block' if (analysis_result['is_malicious'] or ml_prediction['is_phishing']) else 'safe'
    }
    
    return jsonify(result)

if __name__ == '__main__':
    # Create temp directory if it doesn't exist
    os.makedirs('temp', exist_ok=True)
    app.run(debug=True)