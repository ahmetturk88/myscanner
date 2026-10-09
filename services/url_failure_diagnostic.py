"""No exception message, URL, query, local variable or credential in diagnostics."""
import traceback
from pathlib import PurePath


def failure_diagnostic(error, stage):
    allowed={'claim','local_analysis','deep_analysis','save_report'}
    frames=[]
    for frame in traceback.extract_tb(error.__traceback__):
        # Restrict to known project modules and numeric locations, not host paths.
        name=PurePath(frame.filename).name
        if name in {'url_analyzer.py','safe_http.py','url_scan_storage.py','url_assessment.py','tasks.py'}:
            frames.append({'module':name,'line':frame.lineno})
    return {'stage':stage if stage in allowed else 'unknown',
            'type':'UnsafeTargetError' if type(error).__name__=='UnsafeTargetError' else
                   type(error).__name__ if type(error).__name__ in {'ValueError','TypeError','KeyError','RuntimeError','Timeout','ConnectionError'} else 'other',
            'locations':frames[-4:]}
