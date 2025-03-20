import cv2
import pytesseract
import re
import requests

# Set Tesseract OCR path (modify this according to your system)
pytesseract.pytesseract.tesseract_cmd = r"C:\Users\prath\Downloads\tesseract-ocr-w64-setup-5.5.0.20241111.exe"

# Function to extract URLs from images
def extract_urls_from_image(image_path):
    image = cv2.imread(image_path)
    text = pytesseract.image_to_string(image)
    urls = re.findall(r'(https?://\S+)', text)
    return urls

# Function to check if a URL is malicious
def check_url_malicious(url):
    api_endpoint = "https://your-api-endpoint/check"  # Replace with your API
    try:
        response = requests.post(api_endpoint, json={"url": url})
        result = response.json()
        if result["malicious"]:
            return f"⚠️ ALERT: {url} is a phishing link!"
        return f"✅ {url} is safe."
    except Exception as e:
        return f"Error checking URL: {e}"

# Example Usage
if __name__ == "__main__":
    image_path = "C:/Users/prath/OneDrive/Documents/phishing-detection/api/sample_phishing.png"
 # actual image path
    urls = extract_urls_from_image(image_path)
    
    if urls:
        for url in urls:
            print(check_url_malicious(url))
    else:
        print("No URLs found in the image.")
