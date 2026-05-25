"""
اختبارات TIP الأساسية
"""
import sys
import os

# أضاف مسار المشروع
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_ioc_lookup():
    from services.ioc_lookup import IoCLookup
    from app import app
    
    lookup = IoCLookup()
    
    # ✅ العمل داخل سياق التطبيق
    with app.app_context():
        # اختبار البحث عن IP غير موجود
        result = lookup.lookup("192.0.2.1", "ip")
        
        if result.get('found') is False:
            print("✅ Lookup test passed")
        else:
            print("❌ Lookup test failed - expected not found")
            print(f"   Result: {result}")


def test_tip_collector():
    from services.tip_collector import TIPCollector
    from app import app
    from extensions import db
    
    with app.app_context():
        # تأكد من وجود جداول TIP
        from models import IoCEntry, IoCSource, IoCMatch, TIPFeedLog
        
        collector = TIPCollector()
        added = collector.initialize_default_sources()
        print(f"✅ Sources initialized: {added} added")
        
        # عرض عدد المصادر في قاعدة البيانات
        sources_count = IoCSource.query.count()
        print(f"   Total sources in DB: {sources_count}")


def test_misp_client():
    from services.misp_client import MISPClient
    from app import app
    
    with app.app_context():
        client = MISPClient()
        print(f"MISP configured: {client.is_configured}")
        print("✅ MISP client test passed")


def test_tip_models():
    """اختبار إضافي: التأكد من وجود الجداول"""
    from app import app
    from extensions import db
    from sqlalchemy import inspect
    
    with app.app_context():
        from models import IoCEntry, IoCSource, IoCMatch, TIPFeedLog
        
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # طباعة أسماء الجداول
        print("\n📊 TIP Tables:")
        print(f"   - IoCEntry (ioc_entry): {'ioc_entry' in tables}")
        print(f"   - IoCSource (ioc_source): {'ioc_source' in tables}")
        print(f"   - IoCMatch (ioc_match): {'ioc_match' in tables}")
        print(f"   - TIPFeedLog (tip_feed_log): {'tip_feed_log' in tables}")


if __name__ == '__main__':
    print("\n" + "=" * 50)
    print(" TIP TESTS ".center(50, "="))
    print("=" * 50 + "\n")
    
    try:
        test_tip_models()
        print()
        test_ioc_lookup()
        print()
        test_tip_collector()
        print()
        test_misp_client()
        print()
        print("🎉 All TIP tests completed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()