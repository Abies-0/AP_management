import re
import redis
import bcrypt
import datetime
from get_config import Config
from mysql_tools import connection

class UserAccount:

    def __init__(self, data):
        self.data = data
        self.db_name = list((Config("database", "config/db.yaml").get()).keys())[0]
        self.r_config = Config("redis", "config/redis.yaml").get()
        self.r = redis.Redis(host=self.r_config["host"], port=self.r_config["port"], db=self.r_config["db"])
        self.para_config = Config("account", "config/para.yaml").get()
        self.un = list(self.para_config[0].keys())[0]
        self.pw = list(self.para_config[1].keys())[0]
        self.un_para = self.para_config[0][self.un]
        self.pw_para = self.para_config[1][self.pw]
        self.result = {"success": False, "reason": None}

    def __check_data(self):
        min_un, max_un = self.un_para["min_length"], self.un_para["max_length"]
        min_pw, max_pw = self.pw_para["min_length"], self.pw_para["max_length"]
        if set(self.data.keys()) != {self.un, self.pw}:
            self.result["reason"] = "Data contains extra fields apart from username and password."
            return
        if not re.match(r"^.{%d,%d}$" % (min_un, max_un), self.data[self.un]):
            self.result["reason"] = "%s length is %d, not in the range between %d and %d" % (self.un, len(self.data[self.un]), min_un, max_un)
            return
        if not re.match(r"^.{%d,%d}$" % (min_pw, max_pw), self.data[self.pw]):
            self.result["reason"] = "%s length is %d, not in the range between %d and %d" % (self.pw, len(self.data[self.pw]), min_pw, max_pw)
            return
        if not re.match(r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)", self.data[self.pw]):
            self.result["reason"] = "%s content is not valid. It must contains at least 1 uppercase letter, 1 lowercase letter and 1 number." % (self.pw)
            return

    def __pw_hash(self, pw):
        return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())

    def __pw_correct(self, pw, hpw):
        return bcrypt.checkpw(pw.encode("utf-8"), hpw)

    def __user_locked(self, username):
        locked_key = "locked_%s" % (username)
        now = datetime.datetime.now()
        if self.r.exists(locked_key):
            remaining = max(0, 60 - (now.timestamp() - float(self.r.get(locked_key))))
            self.result["reason"] = "Error attempting for over 5 times, please wait for a minute and try it again (still remaining for %d sec)." % (int(remaining))
            return

    def __login_attempt(self, username, success):
        key, locked_key = username, "locked_%s" % (username)
        now = datetime.datetime.now()
        if success:
            self.r.delete(key)
            self.result["success"] = True
            self.result["reason"] = "Verify the account successfully."
            return
        if not self.r.exists(key):
            tomorrow = now + datetime.timedelta(days=1)
            expiration_time = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day)
            expiration_seconds = int((expiration_time - now).total_seconds())
            self.r.setex(key, expiration_seconds, 1)
            self.result["reason"] = "Error attempting, please try it again."
            return
        else:
            self.r.incr(key)
            self.result["reason"] = "Error attempting, please try it again."
            if int(self.r.get(key)) > 5:
                if not self.r.exists(locked_key):
                    self.r.setex(locked_key, 60, now.timestamp())
                self.__user_locked(username)
                return

    def create(self):
        self.__check_data()
        if self.result["reason"]:
            return self.result
        un = self.data[self.un]
        pw = self.data[self.pw]
        try:
            with connection(self.db_name) as conn:
                with conn.cursor() as cursor:
                    sql = "select count(*) from account where username = %s"
                    cursor.execute(sql, self.data["username"])
                    res = cursor.fetchone()["count(*)"]
                    if res:
                        self.result["reason"] = "Username %s exists, please try another one." % (un)
                        return self.result
                    else:
                        hpw = self.__pw_hash(pw)
                        sql_c = "insert into account (%s, %s) " % (self.un, self.pw)
                        sql_c += "values (%s, %s)"
                        cursor.execute(sql_c, (un, hpw))
                        conn.commit()
        except Exception as e:
            self.result["reason"] = "Met MySQL error, please contact the technical support staff. Error message: %s" % (e)
            return self.result
        self.result["success"] = True
        self.result["reason"] = "Create the account successfully,"
        return self.result

    def verify(self):
        self.__check_data()
        if self.result["reason"]:
            return self.result
        un = self.data[self.un]
        pw = self.data[self.pw]
        self.__user_locked(un)
        if self.result["reason"]:
            return self.result
        try:
            with connection(self.db_name) as conn:
                with conn.cursor() as cursor:
                    sql = "select password from account where username = %s"
                    cursor.execute(sql, self.data["username"])
                    res = cursor.fetchone()
                    if not res:
                        self.result["reason"] = "Username %s does not exists, please create first." % (un)
                        return self.result
                    else:
                        hpw = res[self.pw]
                        if not self.__pw_correct(pw, hpw):
                            success = False
                        else:
                            success = True
                        self.__login_attempt(un, success)
                        return self.result
        except Exception as e:
            self.result["reason"] = "Met MySQL error, please contact the technical support staff. Error message: %s" % (e)
            return self.result
