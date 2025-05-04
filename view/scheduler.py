import schedule
import time
from auto_updater import AutoUpdater

def run_update():
    print("[INFO] Running Scheduled Update...")
    updater = AutoUpdater()
    updater.run()

def main():
    # run daily at 12:10 AM (local time)
    schedule.every().day.at("00:19").do(run_update)  # Use 24-hour format
    print("[INFO] Scheduler set for 12:10 AM.")

    while True:
        schedule.run_pending()
        next_run = schedule.next_run()
        print(f"[INFO] Next scheduled run at: {next_run}")
        time.sleep(60)  # Check every minute

if __name__ == "__main__":
    main()