from flask import Flask, render_template, request, jsonify
import os, hashlib, requests, time, traceback

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY', '')

def get_bytes_hash(data):
    return hashlib.sha256(data).hexdigest()

def analyze_apk_local(apk_bytes):
    try:
        from androguard.core.apk import APK
        a = APK(apk_bytes, raw=True)
        obfuscated = False

        try:
            permissions = list(a.get_permissions())
        except Exception:
            permissions = []

        if not permissions:
            obfuscated = True

        DANGEROUS_KEYWORDS = [
            'camera','location','record_audio','read_contacts','send_sms',
            'call_phone','read_call_log','write_call_log','process_outgoing_calls',
            'read_sms','receive_sms','access_fine_location','access_coarse_location',
            'request_install_packages','query_all_packages','read_phone_state',
            'read_phone_numbers','get_accounts','use_biometric','use_fingerprint',
            'read_external_storage','write_external_storage','manage_external_storage',
            'system_alert_window','bind_accessibility_service','accessibility',
            'device_admin','install_packages','delete_packages','mount_unmount',
            'change_network_state','read_precise_location','package_usage_stats',
        ]
        dangerous_perms = [p for p in permissions if any(kw in p.lower() for kw in DANGEROUS_KEYWORDS)]
        # APK ning o'z paket nomidan kelgan ruxsatlar ishonchli
        pkg = ''
        try: pkg = a.get_package() or ''
        except: pass
        pkg_prefix = pkg + '.' if pkg else ''
        TRUSTED_PREFIXES = ('android.', 'com.google.', 'com.android.')
        if pkg_prefix:
            TRUSTED_PREFIXES = TRUSTED_PREFIXES + (pkg_prefix,)
        third_party_perms = [p for p in permissions if not any(p.startswith(pr) for pr in TRUSTED_PREFIXES)]

        def safe(fn):
            try: return fn()
            except: return None

        try: activities = list(a.get_activities())
        except: activities = []
        try: services = list(a.get_services())
        except: services = []
        try: receivers = list(a.get_receivers())
        except: receivers = []

        min_sdk = safe(a.get_min_sdk_version)
        target_sdk = safe(a.get_target_sdk_version)

        risk_score = 0
        risk_factors = []

        if obfuscated:
            risk_score += 40
            risk_factors.append({
                'uz': 'APK kuchli himoyalangan (obfuscated) — ruxsatlar o\'qilmadi',
                'en': 'APK is heavily obfuscated — permissions could not be read',
                'ru': 'APK сильно защищён (obfuscated) — разрешения не читаются'
            })
        else:
            if len(dangerous_perms) > 5:
                risk_score += 35
                risk_factors.append({'uz': str(len(dangerous_perms)) + ' ta xavfli ruxsat aniqlandi', 'en': str(len(dangerous_perms)) + ' dangerous permissions found', 'ru': 'Обнаружено ' + str(len(dangerous_perms)) + ' опасных разрешений'})
            elif len(dangerous_perms) > 2:
                risk_score += 20
                risk_factors.append({'uz': str(len(dangerous_perms)) + ' ta xavfli ruxsat', 'en': str(len(dangerous_perms)) + ' dangerous permissions', 'ru': str(len(dangerous_perms)) + ' опасных разрешений'})
            elif len(dangerous_perms) > 0:
                risk_score += 10
                risk_factors.append({'uz': str(len(dangerous_perms)) + ' ta shubhali ruxsat', 'en': str(len(dangerous_perms)) + ' suspicious permissions', 'ru': str(len(dangerous_perms)) + ' подозрительных разрешений'})

            if any('request_install_packages' in p.lower() for p in permissions):
                risk_score += 30
                risk_factors.append({'uz': "Boshqa ilovalarni o'rnatish ruxsati bor", 'en': 'Can install other apps — dropper behavior', 'ru': 'Может устанавливать другие приложения'})

            if any('query_all_packages' in p.lower() for p in permissions):
                risk_score += 20
                risk_factors.append({'uz': "Barcha ilovalarni ko'rishi mumkin (josuslik)", 'en': 'Can enumerate all installed apps — spyware', 'ru': 'Может просматривать все установленные приложения'})

            if any('foreground_service' in p.lower() for p in permissions):
                risk_score += 10
                risk_factors.append({'uz': 'Fonda doim ishlaydi', 'en': 'Runs persistently in background', 'ru': 'Постоянно работает в фоне'})

            if third_party_perms:
                risk_score += 25
                names = ', '.join(third_party_perms[:2])
                risk_factors.append({'uz': "Noma'lum domendan ruxsatlar: " + names, 'en': 'Permissions from unknown domains: ' + names, 'ru': 'Разрешения от неизвестных доменов: ' + names})

            if min_sdk and int(min_sdk) < 21:
                risk_score += 10
                risk_factors.append({'uz': "Juda eski Android versiyasini qo'llab-quvvatlaydi", 'en': 'Supports very old Android version', 'ru': 'Поддерживает очень старую версию Android'})

            if len(receivers) > 15:
                risk_score += 15
                risk_factors.append({'uz': str(len(receivers)) + ' ta broadcast receiver — shubhali', 'en': str(len(receivers)) + ' broadcast receivers — suspicious', 'ru': str(len(receivers)) + ' broadcast receiver — подозрительно'})

        risk_level = 'high' if risk_score >= 50 else 'medium' if risk_score >= 25 else 'low'

        return {
            'package_name': safe(a.get_package),
            'app_name': safe(a.get_app_name),
            'version_name': safe(a.get_androidversion_name),
            'version_code': safe(a.get_androidversion_code),
            'min_sdk': min_sdk,
            'target_sdk': target_sdk,
            'permissions': permissions,
            'dangerous_permissions': dangerous_perms,
            'third_party_permissions': third_party_perms,
            'activities_count': len(activities),
            'services_count': len(services),
            'receivers_count': len(receivers),
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'obfuscated': obfuscated,
        }
    except Exception as e:
        traceback.print_exc()
        return {'error': str(e), 'obfuscated': False}

def analyze_with_virustotal(apk_bytes, file_hash, api_key=''):
    key = api_key or VIRUSTOTAL_API_KEY
    headers = {'x-apikey': key}
    r = requests.get('https://www.virustotal.com/api/v3/files/' + file_hash, headers=headers)
    if r.status_code == 200:
        return parse_vt_response(r.json())
    upload_r = requests.post('https://www.virustotal.com/api/v3/files',
                             headers=headers,
                             files={'file': ('upload.apk', apk_bytes, 'application/octet-stream')})
    if upload_r.status_code != 200:
        return {'error': 'VirusTotal upload failed. Status: ' + str(upload_r.status_code)}
    analysis_id = upload_r.json().get('data', {}).get('id', '')
    for _ in range(10):
        time.sleep(6)
        res = requests.get('https://www.virustotal.com/api/v3/analyses/' + analysis_id, headers=headers)
        data = res.json()
        if data.get('data', {}).get('attributes', {}).get('status') == 'completed':
            file_id = data.get('meta', {}).get('file_info', {}).get('sha256', file_hash)
            full = requests.get('https://www.virustotal.com/api/v3/files/' + file_id, headers=headers)
            if full.status_code == 200:
                return parse_vt_response(full.json())
    return {'error': 'Timeout — VirusTotal tahlili uzoq davom etdi'}

def parse_vt_response(data):
    attrs = data.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    results = attrs.get('last_analysis_results', {})
    malicious_engines = [n for n, r in results.items() if r.get('category') == 'malicious']
    suspicious_engines = [n for n, r in results.items() if r.get('category') == 'suspicious']
    total = sum(stats.values())
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    if malicious > 5 or (malicious + suspicious) > 10:
        verdict = 'malicious'
    elif malicious > 0 or suspicious > 2:
        verdict = 'suspicious'
    else:
        verdict = 'clean'
    return {
        'stats': stats,
        'total_engines': total,
        'malicious_count': malicious,
        'suspicious_count': suspicious,
        'malicious_engines': malicious_engines[:10],
        'suspicious_engines': suspicious_engines[:5],
        'verdict': verdict,
        'reputation': attrs.get('reputation', 0),
        'vt_link': 'https://www.virustotal.com/gui/file/' + attrs.get('sha256', ''),
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Fayl topilmadi'}), 400
        file = request.files['file']
        api_key = request.form.get('api_key', '').strip()
        if not file or file.filename == '':
            return jsonify({'error': 'Fayl tanlanmagan'}), 400
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'Faqat APK fayllari qabul qilinadi'}), 400

        apk_bytes = file.read()
        file_hash = get_bytes_hash(apk_bytes)
        result = {
            'filename': file.filename,
            'filesize': len(apk_bytes),
            'sha256': file_hash,
        }
        result['local'] = analyze_apk_local(apk_bytes)
        key = api_key or VIRUSTOTAL_API_KEY
        if key:
            vt = analyze_with_virustotal(apk_bytes, file_hash, key)
            result['virustotal'] = vt
            if vt.get('verdict') == 'malicious':
                mal = vt.get('malicious_count', 0)
                result['local']['risk_score'] = min(50 + mal * 2, 100)
                result['local']['risk_level'] = 'high'
                result['local']['risk_factors'] = result['local'].get('risk_factors', []) + [
                    {'uz': 'VirusTotal: ' + str(mal) + ' ta antivirus zararli deb aniqladi', 'en': 'VirusTotal: ' + str(mal) + ' engines detected as malicious', 'ru': 'VirusTotal: ' + str(mal) + ' антивирусов обнаружили угрозу'}
                ]
            elif vt.get('verdict') == 'suspicious':
                result['local']['risk_score'] = max(result['local'].get('risk_score', 0), 40)
                result['local']['risk_level'] = 'medium'
        else:
            result['virustotal'] = {'error': 'API kalit kiritilmagan / API key not provided'}
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'Server xatosi: ' + str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
