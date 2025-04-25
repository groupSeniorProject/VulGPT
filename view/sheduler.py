import schedule
import time
from auto_updater import AutoUpdater

def run_update():
    print("[INFO] Running Scheduled Update...")
    updater = AutoUpdater()
    updater.run()

def main():
    # run daily at 2:00 AM
    schedule.every().day.at("02:00").do(run_update)
    print("[INFO] Starting Scheduler...")
    while True:
        print("Not 2AM yet.")
        schedule.run_pending()
        time.sleep(60)