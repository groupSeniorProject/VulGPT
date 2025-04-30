import asyncio
from datetime import datetime
from osv_extractor import OSVExtractor

class AutoUpdater:
    def __init__(self):
        self.osv_extractor = OSVExtractor()

    def update_osv(self):
        asyncio.run(self.osv_extractor.main())

    def run(self):
        print("\n[INFO] Starting Auto Update...")
        print(f"[INFO] Update started at: {datetime.now()}")
        self.update_osv()
        print(f"[INFO] Update completed at: {datetime.now()}")