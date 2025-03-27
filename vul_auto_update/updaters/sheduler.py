import schedule
import time
from vul_auto_update.updaters.auto_updater import AutoUpdater

def run_update():
    print("[INFO] Running Scheduled Update...")
    updater = AutoUpdater()
    updater.run()

#  run daily at 2:00 AM
schedule.every().day.at("02:00").do(run_update)

if __name__ == "__main__":
    print("[INFO] Starting Scheduler...")
    while True:
        schedule.run_pending()
        time.sleep(60)
