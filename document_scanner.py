import os
import re
import PyPDF2
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
import docx
from url_checker import analyze_url
from ml_model import predict_phishing

def extract_urls_from_pdf(file_path):
    """Extract URLs from PDF file"""
    urls = []
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text = page.extract_text()
                # Simple URL extraction regex
                found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?\S+)?', text)
                for url in found_urls:
                    urls.append({
                        'url': url,
                        'page': page_num + 1,
                        'type': 'text'
                    })
    except Exception as e:
        print(f"Error extracting URLs from PDF: {e}")
    return urls

def extract_urls_from_docx(file_path):
    """Extract URLs from DOCX file"""
    urls = []
    try:
        doc = docx.Document(file_path)
        for i, paragraph in enumerate(doc.paragraphs):
            # Simple URL extraction regex
            found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?\S+)?', paragraph.text)
            for url in found_urls:
                urls.append({
                    'url': url,
                    'paragraph': i + 1,
                    'type': 'text'
                })
    except Exception as e:
        print(f"Error extracting URLs from DOCX: {e}")
    return urls

def extract_url_from_qr(file_path):
    """Extract URL from QR code"""
def extract_url_from_qr(file_path):
    """Extract URL from QR code using qreader"""
    try:
        import qreader
        decoder = qreader.QReader()
        image = cv2.imread(file_path)
        decoded_text = decoder.detect_and_decode(image=image)
        
        if decoded_text and any(decoded_text.startswith(prefix) for prefix in ('http://', 'https://')):
            return decoded_text
    except Exception as e:
        print(f"Error extracting URL from QR: {e}")
    return None

def scan_document(file_path):
    """Scan document for URLs and analyze them"""
    urls = []
    file_extension = os.path.splitext(file_path)[1].lower()
    
    if file_extension == '.pdf':
        urls = extract_urls_from_pdf(file_path)
    elif file_extension in ['.doc', '.docx']:
        urls = extract_urls_from_docx(file_path)
    else:
        return {'error': 'Unsupported file format'}
    
    # Analyze extracted URLs
    results = []
    for url_entry in urls:
        url = url_entry['url']
        analysis = analyze_url(url)
        prediction = predict_phishing(url)
        
        results.append({
            **url_entry,
            'analysis': analysis,
            'prediction': prediction,
            'is_malicious': analysis['is_malicious'] or prediction['is_phishing']
        })
    
    return {
        'document': os.path.basename(file_path),
        'url_count': len(urls),
        'malicious_count': sum(1 for r in results if r['is_malicious']),
        'results': results
    }
