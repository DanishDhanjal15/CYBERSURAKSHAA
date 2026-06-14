import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename

import database
import detector
import scoring

app = Flask(__name__)
# Use a secret key for session management
app.secret_key = secrets.token_hex(24)

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit size to 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize SQLite database on startup
database.init_db()

@app.route('/')
def index():
    """Render the upload and text analysis submission page."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle image upload or text input and run detection engines."""
    input_type = request.form.get('input_type')
    extracted_text = ""
    ocr_confidence = None
    image_url = None

    if input_type == 'image':
        if 'image_file' not in request.files:
            return render_template('index.html', error="No image file part uploaded.")
        file = request.files['image_file']
        if file.filename == '':
            return render_template('index.html', error="No image file selected.")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{secrets.token_hex(4)}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            extracted_text, ocr_confidence = detector.extract_text_from_image(filepath)
            image_url = url_for('static', filename=f"uploads/{unique_filename}")
        else:
            return render_template('index.html', error="Invalid file type. Please upload PNG, JPG, JPEG, or WEBP.")

    elif input_type == 'url':
        image_url_input = request.form.get('image_url', '').strip()
        if not image_url_input:
            return render_template('index.html', error="Please enter an image URL.")
        if not (image_url_input.startswith('http://') or image_url_input.startswith('https://')):
            return render_template('index.html', error="Invalid URL. Must start with http:// or https://")

        try:
            import requests as req
            import re
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            target_url = image_url_input
            resp = req.get(image_url_input, headers=headers, timeout=15, stream=True)
            resp.raise_for_status()

            content_type = resp.headers.get('Content-Type', '')
            
            # If the URL is an HTML webpage, parse it to extract the og:image or twitter:image
            if 'text/html' in content_type:
                full_resp = req.get(image_url_input, headers=headers, timeout=15)
                html_text = full_resp.text
                patterns = [
                    r'<meta\s+[^>]*property=["\']og:image["\']\s+[^>]*content=["\']([^"\']+)["\']',
                    r'<meta\s+[^>]*content=["\']([^"\']+)["\']\s+[^>]*property=["\']og:image["\']',
                    r'<meta\s+[^>]*name=["\']twitter:image["\']\s+[^>]*content=["\']([^"\']+)["\']',
                    r'<meta\s+[^>]*content=["\']([^"\']+)["\']\s+[^>]*name=["\']twitter:image["\']',
                ]
                resolved_url = None
                for pattern in patterns:
                    match = re.search(pattern, html_text, re.IGNORECASE)
                    if match:
                        resolved_url = match.group(1)
                        break
                
                if resolved_url:
                    target_url = resolved_url
                    # Fetch the resolved preview image
                    resp = req.get(target_url, headers=headers, timeout=15, stream=True)
                    resp.raise_for_status()
                    content_type = resp.headers.get('Content-Type', '')
                else:
                    return render_template('index.html', error="This URL is a webpage, but no preview image (og:image) could be found.")

            if not any(ct in content_type for ct in ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/']):
                # Warn but still try — some servers return wrong content-type
                print(f"[SHIELD WARNING] Unexpected Content-Type: {content_type} — attempting OCR anyway")

            # Determine extension from target URL or content-type
            ext = 'jpg'
            url_lower = target_url.lower().split('?')[0]
            for candidate in ['.png', '.jpg', '.jpeg', '.webp']:
                if url_lower.endswith(candidate):
                    ext = candidate.lstrip('.')
                    break
            if 'png' in content_type:
                ext = 'png'
            elif 'webp' in content_type:
                ext = 'webp'

            unique_filename = f"{secrets.token_hex(4)}_url_image.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            with open(filepath, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            extracted_text, ocr_confidence = detector.extract_text_from_image(filepath)
            image_url = url_for('static', filename=f"uploads/{unique_filename}")

        except req.exceptions.ConnectionError:
            return render_template('index.html', error="Could not connect to the URL. Please check the link and try again.")
        except req.exceptions.Timeout:
            return render_template('index.html', error="The request timed out. The image URL may be slow or unavailable.")
        except req.exceptions.HTTPError as e:
            return render_template('index.html', error=f"HTTP error fetching image: {e}")
        except Exception as e:
            return render_template('index.html', error=f"Failed to download image from URL: {e}")

    else:
        extracted_text = request.form.get('pasted_text', '').strip()
        if not extracted_text:
            return render_template('index.html', error="Please enter text or upload an image to analyze.")

    # Parse brand and phone numbers
    brand, brand_method, brand_conf = detector.detect_brand(extracted_text)
    phones = detector.extract_phone_numbers(extracted_text)

    # Process findings
    if not phones:
        # Save placeholder report to session when no phone numbers are found
        session['report'] = {
            'has_phone': False,
            'text': extracted_text,
            'image_url': image_url,
            'brand': brand,
            'risk_score': 0,
            'confidence': 0,
            'severity': 'Safe',
            'reasons': ["No phone numbers detected in the scanned text/image."],
            'recommendation': "No customer care numbers were found. Verification is not applicable.",
            'official_phone': None,
            'official_website': None,
            'previous_reports': 0,
            'detected_phone': None
        }
        return redirect(url_for('results'))

    # If multiple phones are found, analyze the primary (first) one in detail
    primary_phone = phones[0]
    
    # 1. Official verification lookup
    official_contact = database.get_official_contact(brand)
    
    # 2. Threat intelligence database lookup
    threat_intel = database.lookup_indicator(primary_phone['normalized'])
    is_threat_intel = threat_intel is not None
    previous_reports = threat_intel['reports'] if is_threat_intel else 0

    # 3. Calculate Risk Score and details
    risk_score, severity, reasons, recommendation = scoring.calculate_risk_score(
        brand, primary_phone, official_contact, is_threat_intel, previous_reports
    )

    # 4. Calculate Confidence Score
    verified_against_db = official_contact is not None
    confidence_score = scoring.calculate_confidence_score(
        ocr_conf=ocr_confidence,
        brand_conf=brand_conf,
        phone_found=True,
        verified_against_db=verified_against_db,
        threat_intel_matched=is_threat_intel,
        is_image=(input_type == 'image')
    )

    # Compile the final report dictionary
    report = {
        'has_phone': True,
        'text': extracted_text,
        'image_url': image_url,
        'brand': brand,
        'brand_confidence': brand_conf,
        'brand_method': brand_method,
        
        # Phone details
        'detected_phone': primary_phone['original'],
        'normalized_phone': primary_phone['normalized'],
        'phone_type': primary_phone['type'],
        'all_detected_phones': [p['original'] for p in phones],
        
        # Database lookups
        'official_phone': official_contact['official_phone'] if official_contact else "Not Available",
        'official_website': official_contact['official_website'] if official_contact else "Not Available",
        
        # Scoring
        'risk_score': risk_score,
        'confidence': confidence_score,
        'severity': severity,
        'reasons': reasons,
        'recommendation': recommendation,
        'previous_reports': previous_reports,
        'ocr_confidence': round(ocr_confidence, 1) if ocr_confidence is not None else None
    }
    
    # Save to flask session
    session['report'] = report
    return redirect(url_for('results'))

@app.route('/results')
def results():
    """Render the results dashboard for the current analysis session."""
    report = session.get('report')
    if not report:
        return redirect(url_for('index'))
    return render_template('results.html', report=report)

@app.route('/report_scam', methods=['POST'])
def report_scam():
    """AJAX endpoint for marking a phone number as a scam indicator."""
    data = request.get_json()
    if not data or 'phone' not in data:
        return jsonify({'success': False, 'error': 'Missing phone number'}), 400
        
    phone = data['phone']
    new_reports = database.add_or_increment_indicator(phone)
    
    # Update current session if the reported phone matches the analyzed phone
    report = session.get('report')
    if report and report.get('detected_phone') == phone:
        report['previous_reports'] = new_reports
        # Recalculate Risk Score with updated threat intelligence
        official_contact = database.get_official_contact(report['brand'])
        
        primary_phone = {
            'original': report['detected_phone'],
            'normalized': report['normalized_phone'],
            'type': report['phone_type']
        }
        
        risk_score, severity, reasons, recommendation = scoring.calculate_risk_score(
            report['brand'], primary_phone, official_contact, True, new_reports
        )
        
        report['risk_score'] = risk_score
        report['severity'] = severity
        report['reasons'] = reasons
        report['recommendation'] = recommendation
        session['report'] = report
        
        return jsonify({
            'success': True, 
            'reports': new_reports,
            'risk_score': risk_score,
            'severity': severity,
            'reasons': reasons,
            'recommendation': recommendation
        })
        
    return jsonify({'success': True, 'reports': new_reports})

@app.route('/resolve_url')
def resolve_url():
    """AJAX endpoint that inspects a URL and returns the preview image if it's a webpage."""
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'success': False, 'error': 'No URL provided'}), 400
        
    try:
        import requests as req
        import re
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        resp = req.get(url, headers=headers, timeout=10, stream=True)
        resp.raise_for_status()
        
        content_type = resp.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            full_resp = req.get(url, headers=headers, timeout=10)
            html_text = full_resp.text
            patterns = [
                r'<meta\s+[^>]*property=["\']og:image["\']\s+[^>]*content=["\']([^"\']+)["\']',
                r'<meta\s+[^>]*content=["\']([^"\']+)["\']\s+[^>]*property=["\']og:image["\']',
                r'<meta\s+[^>]*name=["\']twitter:image["\']\s+[^>]*content=["\']([^"\']+)["\']',
                r'<meta\s+[^>]*content=["\']([^"\']+)["\']\s+[^>]*name=["\']twitter:image["\']',
            ]
            resolved_url = None
            for pattern in patterns:
                match = re.search(pattern, html_text, re.IGNORECASE)
                if match:
                    resolved_url = match.group(1)
                    break
            
            if resolved_url:
                return jsonify({'success': True, 'resolved_url': resolved_url, 'is_html': True})
            else:
                return jsonify({'success': False, 'error': 'No preview image found on this webpage.'})
        else:
            return jsonify({'success': True, 'resolved_url': url, 'is_html': False})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000, reloader_type='stat')

