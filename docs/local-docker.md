# اختبار MyScanner محليًا عبر Docker

هذه بيئة اختبار للبندين 9 و16، وليست نشر إنتاج أو شراء VPS. تحتاج Docker Desktop مع Linux containers. اسم المشروع myscanner-local؛ لا يغير urlvet-* أو zap-scanner الموجودين. منفذ الموقع 127.0.0.1:8000، بينما url.vet الموجود على host:8080 عبر host.docker.internal. لا تنشر PostgreSQL أو Redis على منافذ المضيف.

## التجهيز

من مجلد المشروع وعلى فرع fix/durable-url-scan-jobs:

```powershell
python scripts/init_local_stack.py
docker compose --env-file .env.docker.local -f compose.local.yml config --quiet
docker compose --env-file .env.docker.local -f compose.local.yml up -d --build
docker compose --env-file .env.docker.local -f compose.local.yml ps -a
```

الأداة تولد أسرار اختبار محلية عشوائية في .env.docker.local وتحافظ على الملف إن كان موجودًا. لا تنسخ SECRET_KEY أو DATABASE_URL أو مفاتيح المزودين من Render. لا تشارك محتوى هذا الملف؛ config --quiet يتحقق دون طباعة القيم. أوامر البيئة تحدد قاعدة جديدة على خدمة postgres باسم myscanner_local؛ لا تتصل بقاعدة اللاب القديمة أو Render. الانتهاء الناجح لخدمة init-db أمر متوقع؛ هي مهمة واحدة لا خدمة دائمة.

ملف requirements الأصلي يحتوي UTF-16 BOM؛ Dockerfile.local يحوله داخل الصورة فقط دون تعديل الاعتماديات. الصورة تسمح بالمصدر فقط وتستبعد .env وGit وقواعد البيانات والكاش والسجلات المحلية، وتعمل تطبيقات Python كمستخدم 10001. أنظمة الملفات الأساسية read-only مع volumes للمجلدات التي يكتب فيها التطبيق. الموارد حدود اختبار أولية، لا تقدير لمواصفات VPS.

## إثبات التنفيذ الفعلي

```powershell
docker compose --env-file .env.docker.local -f compose.local.yml exec web python scripts/local_runtime.py smoke-queue
```

ينشئ سجل اختبار مؤقتًا منتهي المهلة ثم يرسل مهمة expire_url_scan_jobs عبر Redis الحقيقي. تتحقق الأداة من قيام العامل المنفصل بتغيير الحالة في PostgreSQL ثم تنظف سجلها وحسابها المؤقتين. لا تبدأ فحص موقع ولا ترسل ملفات إلى مزود. المهمة تنهي أيضًا أي فحص URL آخر تجاوز مهلته، كما هو سلوكها الطبيعي. هذا يثبت عبور الطابور إلى العامل والكتابة في DB، لا يثبت نجاح تحليل URL أو مهلات SIGKILL أو خطة الاستعادة الكاملة.

انتظر دقيقة بعد التشغيل ثم راجع:

```powershell
docker compose --env-file .env.docker.local -f compose.local.yml logs --tail 40 beat worker
```

يجب رؤية إرسال Beat لمهمة expire-url-scan-jobs واستقبال العامل لها. health worker يستخدم ping إلى اسم العامل المحدد؛ health الويب يفحص HTTP وDB وbroker/backend. لا يوجد health يدعي التحقق من جدولة Beat أو جاهزية المزود الخارجي.

## دخول وتجربة واجهة URL

```powershell
docker compose --env-file .env.docker.local -f compose.local.yml exec web python scripts/local_runtime.py create-user
```

أدخل كلمة مرور محلية خاصة بطول 12 حرفًا أو أكثر ثم أكدها. تنشئ الأداة حساب local-admin@example.invalid مشرفًا ومؤكدًا داخل قاعدة الاختبار فقط؛ ترفض الاتصال بقاعدة مختلفة أو APP_ENV مختلف وترفض تعديل حساب موجود. افتح http://127.0.0.1:8000 وسجّل بهذا الحساب. تحليل رابط تجريبي مثل https://example.com يبدأ من /dashboard ويحفظ النتيجة. إيقاف urlvet-backend مؤقتًا اختبار منفصل متعمد؛ نقص التغطية يجب أن يظهر partial/unknown بدل سلامة مؤكدة. الاختبار لا يضيف مفاتيح مزودين مدفوعة.

## الإيقاف والبيانات

```powershell
docker compose --env-file .env.docker.local -f compose.local.yml stop
```

يحافظ هذا على البيانات. لا تستخدم down -v إلا إذا قررت حذف قاعدة الاختبار والطابور والملفات المحلية نهائيًا. اسم المشروع والـvolumes منفصلان عن الخدمات السابقة. إعادة إنشاء أسرار الملف وحده لا تغير كلمة مرور PostgreSQL المخزنة؛ احتفظ بالملف مع بيئة الاختبار القائمة.

## حدود هذه المرحلة

لا يوجد reverse proxy أو HTTPS محلي؛ APP_ENV=development والواجهة منشورة على loopback فقط وdebug مغلق. الشبكة data داخلية، لكن العامل المتصل بها وبشبكة outbound يملك الوصول إلى DB؛ هذا ليس جدار خروج يمنع SSRF للأدوات الثقيلة. Redis AOF everysec يقلل فقدان بيانات الطابور ولكنه لا يضمن عدم فقد أي رسالة عند انقطاع الطاقة. maxmemory-policy=noeviction يمنع طرد مفاتيح الطابور ويُظهر خطأ عند امتلاء الذاكرة بدل حذفها صامتًا.

تهيئة القاعدة أصبحت خطوة Alembic منفصلة؛ الموقع والعامل لا ينشئان الجداول ولا يعدّلانها أثناء الاستيراد. يجب اختبار الترحيل على PostgreSQL جديد وعلى نسخة مستعادة قبل الإنتاج؛ راجع docs/database-migrations.md. النسخ الاحتياطي والاستعادة وTLS والإلغاء وoutbox/retries ورفع العينات والتنظيف بعد SIGKILL وعزل ZAP/OpenVAS لم تُغلق. الأدوات الثقيلة والاعتماديات الاختيارية غير مضافة بهذه البيئة؛ حدود 1GB للعامل ليست وعدًا بكفايتها لكل خدمة. لا تدمج #35 وتنشره على Render دون تجهيز عامل وطابور هناك؛ المشروع المحلي لا يقدم طابورًا إلى Render.

المراجع: Docker Compose startup order وbuild context، وثائق صورة postgres الرسمية (18: volume /var/lib/postgresql)، ووثائق Celery Redis/key eviction. لا يوجد Docker daemon في بيئة المساعد؛ نجاح build والتشغيل ينتظر اختبار المستخدم.
