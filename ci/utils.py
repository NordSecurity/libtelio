import subprocess
import time
import traceback
from datetime import datetime


def run_with_retry(fn, retries=3, delay=3, exceptions=(Exception,)):
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except exceptions as e:
            print(f"[{datetime.now()}] Attempt {attempt} failed with exception:")
            if isinstance(e, subprocess.CalledProcessError):
                print("stdout:", e.stdout.decode() if e.stdout else "None")
                print("stderr:", e.stderr.decode() if e.stderr else "None")
            else:
                traceback.print_exc()
            if attempt < retries:
                time.sleep(delay)
            else:
                raise
