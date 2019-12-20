from datetime import datetime


class Timer:
    @staticmethod
    def get_time():
        time = datetime.today()
        sec = datetime.timestamp(time)
        return int(sec), time.microsecond
