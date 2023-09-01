import os
import csv

from reNgine.settings import RENGINE_HOME


def is_safe_path(basedir, path, follow_symlinks=True):
    # Source: https://security.openstack.org/guidelines/dg_using-file-paths.html
    # resolves symbolic links
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))


# Source: https://stackoverflow.com/a/10408992
def remove_lead_and_trail_slash(s):
    if s.startswith("/"):
        s = s[1:]
    if s.endswith("/"):
        s = s[:-1]
    return s


def get_time_taken(latest, earlier):
    duration = latest - earlier
    days, seconds = duration.days, duration.seconds
    hours = days * 24 + seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    if not hours and not minutes:
        return "{} seconds".format(seconds)
    elif not hours:
        return "{} minutes".format(minutes)
    elif not minutes:
        return "{} hours".format(hours)
    return "{} hours {} minutes".format(hours, minutes)


# Function made to replace "whatportis" module not updated
def whatportis(port: int):
    try:
        # File from https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
        path = os.path.join(RENGINE_HOME, "static/IANA-service-names-port-numbers.csv")
        with open(path, "r") as f:
            ports = csv.DictReader(f)
            for line in ports:
                if line["port"] == str(port):
                    return line

        return {"port": str(port), "name": "custom", "description": "Custom port"}

    except IOError:
        return {"port": str(port), "name": "error", "description": "Error"}
