import os
import pymysql
from logger import ConcurrentLogger
from get_config import Config

log_path = "./logs/mysql"
os.makedirs(log_path, exist_ok=True)
error_log = ConcurrentLogger(filename="%s/conn_err.log" % (log_path))

def connection_init():
    config = Config("database", "config/db.yaml").get()
    init = list(config.values())[0]
    try:
        connection = (
                pymysql.connect(
                    host=init["host"],
                    user=init["user"],
                    password=init["password"],
                    port=init["port"],
                    )
                )
        return connection
    except Exception as e:
        error_log.error(e)

def connection(db_name):
    config = Config("database", "config/db.yaml").get()[db_name]
    try:
        connection = (
                pymysql.connect(
                    host=config["host"],
                    user=config["user"],
                    password=config["password"],
                    port=config["port"],
                    db=db_name,
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor
                    )
                )
        return connection
    except Exception as e:
        error_log.error(e)

def check_db_exist(db_name):
    with connection_init() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select count(*) as count from information_schema.schemata where schema_name = %s", (db_name))
            result = cursor.fetchone()
    if result[0] > 0:
        return True
    return False

def check_table_exist(db_name, table_name):
    with connection(db_name) as conn:
        with conn.cursor() as cursor:
            cursor.execute("show tables like %s", (table_name))
            return cursor.fetchone() is not None

def create_table(db_name):
    tables = Config(db_name, "config/schema.yaml").get()
    with connection(db_name) as conn:
        with conn.cursor() as cursor:
            for table in tables:
                tn = table["table_name"]
                tc = table["column"]
                query = "create table if not exists %s (" % (tn)
                for col in tc:
                    query += "%s %s %s %s, " % (col["name"], col["type"], col["null"], col["extra"])
                query = query[:-2] + ")"
                cursor.execute(query)

def create_db(db_name):
    exist = check_db_exist(db_name)
    if not exist:
        with connection_init() as conn:
            with conn.cursor() as cursor:
                cursor.execute("create database if not exists %s" % (db_name))
                create_table(db_name)
