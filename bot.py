import asyncio, requests, logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
FLASK_URL = os.environ.get('FLASK_URL', 'http://127.0.0.1:5000/analyze')

# Til sozlamalari
USER_LANG = {}

T = {
    'uz': {
        'start': (
            "🛡 *APK Xavfsizlik Tahlilchisi*\n\n"
            "APK faylni yuboring — men uni VirusTotal va mahalliy tahlil orqali tekshiraman.\n\n"
            "📎 Faylni to'g'ridan-to'g'ri shu chatga yuboring."
        ),
        'lang_set': "✅ Til o'zbekchaga o'zgartirildi!",
        'waiting': "⏳ APK tahlil qilinmoqda...\nVirusTotal tekshiruvi 30-60 soniya olishi mumkin.",
        'only_apk': "⚠️ Faqat `.apk` fayl yuboring!",
        'error': "❌ Xatolik yuz berdi: ",
        'flask_err': "❌ Flask server ishlamayapti. Avval `python app.py` ni ishga tushiring.",
        'verdict_mal': "🚨 XAVFLI — Zararli dastur aniqlandi!",
        'verdict_sus': "⚠️ SHUBHALI — Ehtiyot bo'ling!",
        'verdict_clean': "✅ XAVFSIZ — Muammo aniqlanmadi",
        'obf': "🔒 APK kuchli himoyalangan (obfuscated) — ruxsatlar o'qilmadi",
        'app_info': "📱 *Ilova ma'lumotlari*",
        'pkg': "Paket",
        'appname': "Nom",
        'size': "Hajm",
        'risk': "Xavf darajasi",
        'perms': "Ruxsatlar",
        'dang': "xavfli",
        'norm': "oddiy",
        'risk_factors': "⚠️ *Xavf omillari*",
        'vt': "🔬 *VirusTotal natijasi*",
        'mal_engines': "Zararli dedi",
        'clean_engines': "Xavfsiz dedi",
        'detected_by': "Aniqlaganlar",
        'vt_link': "🔗 To'liq hisobot",
        'low': "Past xavf 🟢",
        'medium': "O'rta xavf 🟡",
        'high': "Yuqori xavf 🔴",
    },
    'en': {
        'start': (
            "🛡 *APK Security Analyzer*\n\n"
            "Send an APK file — I'll analyze it using VirusTotal and local analysis.\n\n"
            "📎 Just send the file directly to this chat."
        ),
        'lang_set': "✅ Language set to English!",
        'waiting': "⏳ Analyzing APK...\nVirusTotal scan may take 30-60 seconds.",
        'only_apk': "⚠️ Please send only `.apk` files!",
        'error': "❌ Error occurred: ",
        'flask_err': "❌ Flask server is not running. Please start `python app.py` first.",
        'verdict_mal': "🚨 DANGEROUS — Malware detected!",
        'verdict_sus': "⚠️ SUSPICIOUS — Exercise caution!",
        'verdict_clean': "✅ SAFE — No threats detected",
        'obf': "🔒 APK is heavily obfuscated — permissions could not be read",
        'app_info': "📱 *App Information*",
        'pkg': "Package",
        'appname': "Name",
        'size': "Size",
        'risk': "Risk Score",
        'perms': "Permissions",
        'dang': "dangerous",
        'norm': "normal",
        'risk_factors': "⚠️ *Risk Factors*",
        'vt': "🔬 *VirusTotal Result*",
        'mal_engines': "Flagged by",
        'clean_engines': "Clean by",
        'detected_by': "Detected by",
        'vt_link': "🔗 Full Report",
        'low': "Low risk 🟢",
        'medium': "Medium risk 🟡",
        'high': "High risk 🔴",
    },
    'ru': {
        'start': (
            "🛡 *APK Анализатор безопасности*\n\n"
            "Отправьте APK файл — я проверю его через VirusTotal и локальный анализ.\n\n"
            "📎 Просто отправьте файл в этот чат."
        ),
        'lang_set': "✅ Язык изменён на русский!",
        'waiting': "⏳ Анализ APK...\nПроверка VirusTotal может занять 30-60 секунд.",
        'only_apk': "⚠️ Отправляйте только `.apk` файлы!",
        'error': "❌ Произошла ошибка: ",
        'flask_err': "❌ Flask сервер не запущен. Сначала запустите `python app.py`.",
        'verdict_mal': "🚨 ОПАСНО — Обнаружена вредоносная программа!",
        'verdict_sus': "⚠️ ПОДОЗРИТЕЛЬНО — Будьте осторожны!",
        'verdict_clean': "✅ БЕЗОПАСНО — Угроз не обнаружено",
        'obf': "🔒 APK сильно защищён (obfuscated) — разрешения не читаются",
        'app_info': "📱 *Информация о приложении*",
        'pkg': "Пакет",
        'appname': "Название",
        'size': "Размер",
        'risk': "Уровень риска",
        'perms': "Разрешения",
        'dang': "опасных",
        'norm': "обычных",
        'risk_factors': "⚠️ *Факторы риска*",
        'vt': "🔬 *Результат VirusTotal*",
        'mal_engines': "Обнаружили",
        'clean_engines': "Безопасно по",
        'detected_by': "Обнаружили",
        'vt_link': "🔗 Полный отчёт",
        'low': "Низкий риск 🟢",
        'medium': "Средний риск 🟡",
        'high': "Высокий риск 🔴",
    }
}

def t(uid, key):
    lang = USER_LANG.get(uid, 'uz')
    return T[lang].get(key, key)

def fmt_bytes(b):
    if b < 1048576: return f"{b/1024:.1f} KB"
    return f"{b/1048576:.2f} MB"

def build_result_text(data, uid):
    local = data.get('local', {})
    vt = data.get('virustotal', {})
    risk = local.get('risk_level', 'low')
    vt_verdict = vt.get('verdict', 'unknown')
    obf = local.get('obfuscated', False)

    bad = vt_verdict == 'malicious' or risk == 'high'
    med = vt_verdict == 'suspicious' or risk == 'medium'

    verdict = t(uid,'verdict_mal') if bad else t(uid,'verdict_sus') if med else t(uid,'verdict_clean')

    lines = [f"*{verdict}*\n"]

    if obf:
        lines.append(f"_{t(uid,'obf')}_\n")

    lines.append(t(uid, 'app_info'))
    lines.append(f"• {t(uid,'pkg')}: `{local.get('package_name') or '-'}`")
    lines.append(f"• {t(uid,'appname')}: {local.get('app_name') or '-'}")
    lines.append(f"• {t(uid,'size')}: {fmt_bytes(data.get('filesize',0))}")
    lines.append(f"• SHA-256: `{data.get('sha256','')[:16]}...`\n")

    rs = local.get('risk_score', 0)
    rl = local.get('risk_level', 'low')
    risk_label = t(uid, rl)
    lines.append(f"📊 *{t(uid,'risk')}:* {rs}/100 — {risk_label}")

    perms = local.get('permissions', [])
    dang = local.get('dangerous_permissions', [])
    if perms:
        lines.append(f"🔑 *{t(uid,'perms')}:* {len(dang)} {t(uid,'dang')} · {len(perms)-len(dang)} {t(uid,'norm')}")
        if dang:
            dang_short = ', '.join([p.replace('android.permission.','') for p in dang[:5]])
            lines.append(f"  ⛔ {dang_short}")

    rf = local.get('risk_factors', [])
    if rf:
        lines.append(f"\n{t(uid,'risk_factors')}")
        lang = USER_LANG.get(uid, 'uz')
        for f in rf[:5]:
            txt = f.get(lang) or f.get('uz','')
            lines.append(f"  ▸ {txt}")

    lines.append(f"\n{t(uid,'vt')}")
    if vt.get('error'):
        lines.append(f"❌ {vt['error']}")
    elif vt.get('stats'):
        mal = vt.get('malicious_count', 0)
        cl = vt.get('stats', {}).get('undetected', 0)
        total = vt.get('total_engines', 0)
        lines.append(f"• {t(uid,'mal_engines')}: *{mal}* / {total}")
        lines.append(f"• {t(uid,'clean_engines')}: {cl} / {total}")
        engines = vt.get('malicious_engines', [])
        if engines:
            lines.append(f"• {t(uid,'detected_by')}: {', '.join(engines[:6])}")

    return '\n'.join(lines)

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🇺🇿 O'zbek", callback_data='lang_uz'),
         InlineKeyboardButton("🇬🇧 English", callback_data='lang_en'),
         InlineKeyboardButton("🇷🇺 Русский", callback_data='lang_ru')]
    ])
    await update.message.reply_text(t(uid, 'start'), parse_mode='Markdown', reply_markup=kb)

async def lang_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id
    lang = query.data.replace('lang_', '')
    USER_LANG[uid] = lang
    await query.edit_message_text(t(uid, 'lang_set') + '\n\n' + t(uid, 'start'), parse_mode='Markdown',
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("🇺🇿 O'zbek", callback_data='lang_uz'),
            InlineKeyboardButton("🇬🇧 English", callback_data='lang_en'),
            InlineKeyboardButton("🇷🇺 Русский", callback_data='lang_ru')
        ]]))

async def handle_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    doc = update.message.document

    if not doc or not doc.file_name.lower().endswith('.apk'):
        await update.message.reply_text(t(uid, 'only_apk'), parse_mode='Markdown')
        return

    msg = await update.message.reply_text(t(uid, 'waiting'), parse_mode='Markdown')

    try:
        tg_file = await ctx.bot.get_file(doc.file_id)
        apk_bytes = await tg_file.download_as_bytearray()

        try:
            resp = requests.post(
                FLASK_URL,
                files={'file': (doc.file_name, bytes(apk_bytes), 'application/octet-stream')},
                data={'api_key': ''},
                timeout=120
            )
            data = resp.json()
        except requests.exceptions.ConnectionError:
            await msg.edit_text(t(uid, 'flask_err'), parse_mode='Markdown')
            return

        result_text = build_result_text(data, uid)

        # VT link
        vt = data.get('virustotal', {})
        kb = None
        if vt.get('vt_link'):
            kb = InlineKeyboardMarkup([[InlineKeyboardButton(t(uid,'vt_link'), url=vt['vt_link'])]])

        await msg.edit_text(result_text, parse_mode='Markdown', reply_markup=kb)

    except Exception as e:
        logging.exception(e)
        await msg.edit_text(t(uid, 'error') + str(e))

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler('start', start))
    app.add_handler(CallbackQueryHandler(lang_callback, pattern='^lang_'))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    print("Bot ishga tushdi...")
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
