# APK Tahlil Tizimi / APK Security Analyzer

## O'rnatish / Installation

```bash
pip install flask androguard requests
```

## Ishga tushirish / Run

```bash
python app.py
```

Brauzerda oching / Open in browser:
http://localhost:5000

## VirusTotal API kalit olish / Get API Key

1. https://www.virustotal.com/gui/join-us — ro'yxatdan o'ting (bepul)
2. Profile → API Key bo'limiga o'ting
3. API kalitni nusxa olib, ilovaga kiriting

## Imkoniyatlar / Features

- APK fayl yuklab tahlil qilish
- Xavfli ruxsatlarni aniqlash (kamera, joylashuv, SMS va boshqalar)
- VirusTotal orqali 70+ antivirus bilan tekshirish
- Xavf darajasini hisoblash (0-100)
- Ikki tilli interfeys (O'zbek / English)
- Ilova metadata (paket nomi, versiya, SDK)

## Loyiha tuzilmasi / Structure

```
apk_analyzer/
├── app.py          # Flask backend
├── templates/
│   └── index.html  # Web interfeys
└── uploads/        # Vaqtinchalik fayllar (avtomatik tozalanadi)
```
