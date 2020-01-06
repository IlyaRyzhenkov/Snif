from datetime import datetime
from threading import Thread
import time


class Timer:
    def __init__(self):
        self.init_time = datetime.today()

    def update_timer(self):
        self.init_time = datetime.today()

    @staticmethod
    def get_time():
        time = datetime.today()
        sec = datetime.timestamp(time)
        return int(sec), time.microsecond

    def get_time_delta(self):
        return (datetime.today() - self.init_time).total_seconds()


class IntervalTimer(Thread):
    def __init__(self, interval, stat_mng):
        Thread.__init__(self)
        self.interval = interval
        self.mng = stat_mng

    def run(self):
        while True:
            time.sleep(self.interval)
            self.mng.pack_measure()
