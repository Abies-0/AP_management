import os
import json
from flask import Flask, request as req, jsonify
from flask_cors import CORS
from logger import ConcurrentLogger
from mysql_tools import create_table
from get_config import Config
from source import UserAccount

app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
base_path = "logs"
c_path = "%s/create" % (base_path)
v_path = "%s/verify" % (base_path)
ar_path = "%s/after_request" % (base_path)
os.makedirs(c_path, exist_ok=True)
os.makedirs(v_path, exist_ok=True)
os.makedirs(ar_path, exist_ok=True)
log_c = ConcurrentLogger(filename="%s/create.log" % (c_path))
log_v = ConcurrentLogger(filename="%s/verify.log" % (v_path))
log_ar = ConcurrentLogger(filename="%s/after_request.log" % (ar_path))

db_name = list((Config("database", "config/db.yaml").get()).keys())[0]
create_table(db_name)

def mask_pw(pw):
    return pw[:-5] + "*" * 5 if len(pw) >= 5 else "*" * len(pw)

@app.route("/api/v1/home", methods=["GET"])
def home():
    ret = {
            "Create": "Create account",
            "Verify": "verify account and pasword"
            }
    return jsonify(ret)

@app.route("/api/v1/create", methods=["POST"])
def create():
    try:
        req_body = req.get_json()
        log_c.info("username: %s, password: %s" % (req_body["username"], mask_pw(req_body["password"])))
    except Exception as e:
        resp = {"success": False, "reason": "InputError: %s" % (e)}
        log_c.error(e)
        return resp
    resp = UserAccount(req_body).create()
    log_c.info(resp)
    return resp

@app.route("/api/v1/verify", methods=["POST"])
def verify():
    try:
        req_body = req.get_json()
        log_v.info("username: %s, password: %s" % (req_body["username"], mask_pw(req_body["password"])))
    except Exception as e:
        resp = {"success": False, "reason": "InputError: %s" % (e)}
        log_v.error(e)
        return resp
    resp = UserAccount(req_body).verify()
    log_v.info(resp)
    return resp

@app.after_request
def after_request(resp):
    log_ar.info("\t%s - - [%s] %s %d -" % (req.remote_addr, req.method, req.path, resp.status_code))
    return resp
