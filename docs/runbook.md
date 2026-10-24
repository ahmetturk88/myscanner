# دليل التشغيل (صفحة وحدة)

كل الأوامر على السيرفر من `~/myscanner`. الاختصار `dc` هو:
`docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml -f compose.app-egress.yml -f compose.launch.yml`
ملف الإعدادات هو `.env.vps.rehearsal` (مش `.env`).

## نشر نسخة جديدة
```
git pull --ff-only && dc up -d --build
dc ps                      # كل الخدمات running و healthy
curl -s -o /dev/null -w "%{http_code}\n" https://myscanners.com/   # 200
```
**الرجوع لنسخة سابقة:** `git log --oneline -5`، بعدين `git checkout <commit>` و `dc up -d --build`، وبعد الإصلاح `git checkout main && git pull`.

## لما شي يوقف
| العَرَض | شو تعمل |
|---|---|
| الموقع ما بيفتح | `dc ps` ثم `dc logs --tail 100 proxy web` |
| الفحوص بتضل «جارية» | `dc logs --tail 100 worker` ثم `dc restart worker` |
| بعد إعادة تشغيل السيرفر | `sudo scripts/vps_autostart.sh status`، وإذا لزم `sudo scripts/vps_autostart.sh start` |
| مصدر خارجي عم يعطي مشاكل أو شروطه مش مؤكدة | ضيفه لـ `MYSCANNER_DISABLED_SOURCES` بملف الإعدادات (مثلاً `urlhaus,abuseipdb`) ثم `dc up -d web worker`. الأسماء بـ `services/source_switches.py` |
| أخطاء كتير | Sentry (إذا مفعّل) أو `dc logs --since 30m web worker` |

## التنبيهات
- **النسخ الاحتياطي:** `scripts/vps_backup.sh` يومياً، وبيبعت نبضة لـ `HEALTHCHECK_URL` (بـ `/etc/myscanner/backup.env`).
- **الخدمات:** مرة وحدة `sudo scripts/vps_watch.sh install`، وحط رابط فحص healthchecks.io جديد (مدة 5 دقايق) بـ `/etc/myscanner/watch.env`. للتجربة: `sudo scripts/vps_watch.sh check`.

## تجربة الاسترجاع (مرة بالشهر)
```
sudo scripts/vps_restore_check.sh
```
بيسترجع آخر نسخة بحاوية مؤقتة بلا شبكة، وبيقارن الجداول وعدد الصفوف مع القاعدة الحية. النتيجة لازم تكون PASS. سجّل التاريخ والنتيجة بجدول «سجل التجارب» تحت.
النسخة الخارجية مشفّرة بـ age؛ مفتاح فكّ التشفير عندك بس، وما بيتحط على السيرفر أبداً.

## شغلات دورية
| متى | الأمر |
|---|---|
| أول كل شهر | `python3 scripts/update_dbip.py` (قاعدة موقع الـ IP؛ بتنقرأ بلا إعادة تشغيل) |
| أول كل شهر | تجربة الاسترجاع فوق |
| بعد كل نسخة تطبيق على Play | `sudo python3 scripts/app_release.py --latest N --min N` ثم `dc up -d web` |
| كل أسبوع | إحصائيات Pro: `https://myscanners.com/admin/pro-interest` |

## اختبار الضغط (20 مستخدم بنفس اللحظة)
```
python3 scripts/load_test.py            # بيسأل عن إيميل حساب الأدمن وكلمة السر بشكل مخفي
python3 scripts/load_test.py --no-url-scan   # بدون فحص الروابط الكامل (الأتقل)
```
شغّله بوقت هادي. بيفحص بس دوميننا. النتيجة المطلوبة: PASS، و p95 للصفحات تحت ثانية وحدة.

## سجل التجارب
| التاريخ | التجربة | النتيجة | ملاحظات |
|---|---|---|---|
| | تجربة الاسترجاع | | |
| | اختبار 20 مستخدم | | |
