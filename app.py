import atexit
import secrets
import time
from os import environ

import pymongo
from apscheduler.schedulers.background import BackgroundScheduler
from bson.objectid import ObjectId
from flask import Flask, render_template, redirect, request, json, url_for, abort
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from paho.mqtt import publish
from paho.mqtt.client import Client
from werkzeug.security import generate_password_hash, check_password_hash

grant_codes = {}

app = Flask(__name__)
app.secret_key = environ.get("APP_SECRET_KEY")

login_manager = LoginManager(app)
login_manager.login_view = "login"

client = pymongo.MongoClient(environ.get("DATABASE_URL"))
db = client["data"]
cursor = ""


# noinspection PyShadowingBuiltins
def log_request(type, id, message):
    file = open("request.log", "a")
    file.write("[" + date_str() + " | " + time_str() + "] " + str(id) + " | " + str(type) + " | " + str(message) + "\n")
    file.close()


def log_exception(message, code):
    file = open("exception.log", "a")
    file.write("[" + date_str() + " | " + time_str() + "] " + str(code) + " | " + str(message) + "\n")
    file.close()


def date_str():
    r_date = str(time.localtime().tm_mday) + '.' + str(time.localtime().tm_mon) + '.' + str(time.localtime().tm_year)
    return r_date


def time_str():
    r_time = str(time.localtime().tm_hour) + ':' + str(time.localtime().tm_min) + ':' + str(time.localtime().tm_sec)
    return r_time


stop = False
sid = 0
client = Client("Python")


# noinspection PyUnusedLocal,PyShadowingNames
def on_message(client, userdata, message):
    global stop
    stop = True
    db["sensors"].update_one({"_id": ObjectId(sid)}, {"$set": {"value": float(message.payload.decode("utf-8"))}})


# noinspection PyBroadException
def get_sensors():
    for i in db["sensors"].find():
        try:
            client.reinitialise("Python")
            global stop, sid
            stop = False
            sid = str(i["_id"])
            info = db["controllers"].find_one({"_id": ObjectId(i["controller_id"])})
            client.username_pw_set(info["mqtt_login"], password=info["mqtt_pass"])
            client.on_message = on_message
            
            client.connect(info["mqtt_server"], port=int(info["mqtt_port"]))
            client.loop_start()
            client.subscribe(i["topic"])
            
            start = time.time()
            while time.time() - start < 1:
                if stop:
                    break
            client.disconnect()
        except Exception:
            pass


scheduler = BackgroundScheduler()
scheduler.add_job(func=get_sensors, trigger="interval", seconds=5, max_instances=3)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())


# noinspection PyMethodMayBeStatic
class User(object):
    def __init__(self, id_):
        self.id = id_
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)
    
    @staticmethod
    def get(userid):
        user = db["users"].find_one({"_id": ObjectId(userid)})
        if user is None:
            return None
        else:
            return User(userid)


@login_manager.user_loader
def load_user(userid):
    return User.get(userid)


@app.route('/login_for_yandex', methods=['GET', 'POST'])
def login_ya():
    if request.method == 'GET':
        get_data = request.args
        return render_template("login.html", redirect_uri=get_data.get('redirect_uri'), state=get_data.get('state'),
                               client_id=get_data.get('client_id'), action="/login_for_yandex")
    else:
        data = request.form
        user = db["users"].find_one({"email": data.get("email")})
        if user is None:
            return render_template("login.html", redirect_uri=data.get('redirect_uri'), state=data.get('state'),
                                   client_id=data.get('client_id'), message="Неверный email или пароль",
                                   action="/login_for_yandex")
        elif not check_password_hash(user["password"], data.get("password")):
            return render_template("login.html", redirect_uri=data.get('redirect_uri'), state=data.get('state'),
                                   client_id=data.get('client_id'), message="Неверный email или пароль",
                                   action="/login_for_yandex")
        else:
            code = secrets.token_urlsafe(10)
            grant_codes[code] = str(user["_id"])
            return redirect(
                data.get('redirect_uri') + "?code=" + code + "&state=" + data.get('state') + "&client_id=" + data.get(
                    'client_id') + "&scope=scope")


@app.route('/token', methods=['GET', 'POST'])
def f_token():
    data = request.form
    if data.get("client_secret") == environ.get("YANDEX_SECRET_KEY") and data.get(
            'client_id') == "alice_app" and data.get("grant_type") == "authorization_code" and data.get(
            'code') in grant_codes.keys():
        token = secrets.token_urlsafe()
        id_ = grant_codes.pop(data.get('code'))
        db["tokens"].insert_one({"id": id_, "token": generate_password_hash(token)})
        return '{"access_token":"' + str(id_) + '#' + token + '", "token_type":"bearer"}'
    else:
        abort(401)


@app.route('/reg_user/', methods=['GET', 'POST'])
def reg():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    if request.method == "GET":
        return render_template("reg.html")
    else:
        data = request.form
        user = db["users"].find_one({"email": data.get("email")})
        if user is None:
            db["users"].insert_one({"email": data.get("email"),
                                    "password": generate_password_hash(data.get("password")),
                                    "def_mqtt_server": None, "def_mqtt_login": None, "def_mqtt_pass": None,
                                    "def_mqtt_port": None})
            return redirect(url_for("login"))
        else:
            return render_template("reg.html", message="Данный email занят")


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))
    if request.method == 'GET':
        return render_template("login.html", action="/login")
    else:
        data = request.form
        user = db["users"].find_one({"email": data.get("email")})
        if user is None:
            return render_template("login.html", message="Неверный email или пароль", action="/login")
        elif not check_password_hash(user["password"], data.get("password")):
            return render_template("login.html", message="Неверный email или пароль", action="/login")
        else:
            login_user(User(str(user["_id"])), data.get("remember"))
            return redirect(url_for("profile"))


@app.route('/')
def menu():
    return render_template("menu.html")


@app.route('/v1.0', methods=['HEAD'])
def ping_endpoint_url():
    return 'OK'


# noinspection PyShadowingBuiltins,DuplicatedCode
@app.route('/v1.0/user/unlink', methods=['POST'])
def unlink():
    a_token = request.headers.get("Authorization")
    req_id = request.headers.get("X-Request-Id")
    id = a_token.split("#")[0].split(" ")[1]
    token = a_token.split("#")[1]
    tokens = db["tokens"].find({"id": id}, {"token": 1})
    valid = False
    valid_token = ""
    for i in tokens:
        valid = check_password_hash(i["token"], token)
        if valid:
            valid = i["token"]
            break
    if not valid:
        log_request("unlinking", str(req_id), str(a_token) + " unlinking error")
        return "{'response' : 'not valid token'}"
    else:
        db["tokens"].delete_one({"token": valid_token})
        log_request("unlinking", str(req_id), str(a_token) + " unlinked")
        return '{"request_id": "%s"}' % str(req_id)


# noinspection PyShadowingBuiltins,DuplicatedCode
@app.route('/v1.0/user/devices', methods=['GET'])
def get_devices():
    a_token = request.headers.get("Authorization")
    req_id = request.headers.get("X-Request-Id")
    id = a_token.split("#")[0].split(" ")[1]
    token = a_token.split("#")[1]
    tokens = db["tokens"].find({"id": id}, {"token": 1})
    valid = False
    for i in tokens:
        valid = check_password_hash(i[0], token)
        if valid:
            break
    if not valid:
        log_request("devices", str(req_id), str(a_token) + " auth error")
        abort(403)
    else:
        result = {"request_id": str(req_id)}
        payload = {"user_id": id}
        devices = []
        for i in db["devices"].find({"user_id": id}, {"type": 1, "name": 1, "my_type": 1}):
            device = {"id": str(i["_id"]), "name": i["name"], "type": i["type"]}
            if i["my_type"] == "thermo_gpio":
                device["description"] = "Режимы:\n1 - выкл\n2 - вкл"
            capabilities = []
            for j in db["devices_properties"].find({"device_id": str(i["_id"])}, {"ya_type": 1, "instance": 1}):
                capability = {"type": j["ya_type"]}
                parameters = {"instance": j["instance"]}
                if j["ya_type"] == "devices.capabilities.mode":
                    if i["my_type"] == "thermo_gpio":
                        modes = [{"value": "one"}, {"value": "auto"}, {"value": "two"}]
                        parameters["modes"] = modes
                elif j["ya_type"] == "devices.capabilities.range":
                    if i["my_type"] == "thermo" or i["my_type"] == "thermo_gpio":
                        parameters["unit"] = "unit.temperature.celsius"
                        parameters["range"] = {"min": -50, "max": 50}
                capability["parameters"] = parameters
                capabilities.append(capability)
            device["capabilities"] = capabilities
            properties = []
            for j in db["sensors"].find({"device_id": str(i["_id"])}, {"instance": 1}):
                property = {"type": "devices.properties.float"}
                parameters = {"instance": j["instance"]}
                if j["instance"] == "amperage":
                    parameters["unit"] = "unit.ampere"
                elif j["instance"] == "battery_level":
                    parameters["unit"] = "unit.percent"
                elif j["instance"] == "co2_level":
                    parameters["unit"] = "unit.ppm"
                elif j["instance"] == "humidity":
                    parameters["unit"] = "unit.percent"
                elif j["instance"] == "power":
                    parameters["unit"] = "unit.watt"
                elif j["instance"] == "temperature":
                    parameters["unit"] = "unit.temperature.celsius"
                elif j["instance"] == "voltage":
                    parameters["unit"] = "unit.volt"
                elif j["instance"] == "water_level":
                    parameters["unit"] = "unit.percent"
                property["parameters"] = parameters
                properties.append(property)
            device["properties"] = properties
            devices.append(device)
        payload["devices"] = devices
        result["payload"] = payload
        log_request("devices", str(req_id), str(a_token) + " ok " + str(result))
        return json.dumps(result)


# noinspection PyShadowingBuiltins,PyStatementEffect,DuplicatedCode
@app.route('/v1.0/user/devices/query', methods=['POST'])
def device_state():
    a_token = request.headers.get("Authorization")
    req_id = request.headers.get("X-Request-Id")
    id = a_token.split("#")[0].split(" ")[1]
    token = a_token.split("#")[1]
    tokens = db["tokens"].find({"_id": id}, {"token": 1})
    valid = False
    for i in tokens:
        valid = check_password_hash(i[0], token)
        if valid:
            break
    if not valid:
        log_request("query", str(req_id), str(a_token) + " auth error")
        abort(403)
    else:
        data = json.loads(request.data)
        result = {"request_id": str(req_id)}
        payload = {}
        devices = []
        for i in data["devices"]:
            device = {"id": i["id"]}
            cap = db["devices_properties"].find({"device_id": i["id"]}, {"ya_type": 1, "instance": 1, "value": 1})
            if len(list(cap)) == 0:
                device["error_code"] = "DEVICE_NOT_FOUND"
                device["error_message"] = "Устройство не найдено"
            else:
                capabilities = []
                if db["devices"].find_one({"_id": ObjectId(i["id"])}, {"user_id": 1})["user_id"] != id:
                    abort(403)
                for j in cap:
                    capability = {"type": j["ya_type"]}
                    state = {"instance": j["instance"]}
                    if j["ya_type"] == "devices.capabilities.on_off":
                        state["value"] = j["value"]
                    elif j["ya_type"] == "devices.capabilities.range":
                        state["value"] = int(j["value"])
                    else:
                        state["value"] = j["value"]
                    capability["state"] = state
                    capabilities.append(capability)
                device["capabilities"] = capabilities
                properties = []
                for j in db["sensors"].find({"device_id": int(i["id"])}, {"instance": 1, "value": 1}):
                    property = {"type": "devices.properties.float"}
                    state = {"instance": j["instance"]}
                    value = float(j["value"])
                    if j["instance"] == "amperage" or j["instance"] == "co2_level" or j["instance"] == "power" \
                            or j["instance"] == "voltage":
                        if value < 0:
                            value = 0.0
                    elif j["instance"] == "battery_level" or j["instance"] == "humidity" \
                            or j["instance"] == "water_level":
                        if value < 0:
                            value = 0.0
                        if value > 100:
                            value = 100.0
                    state["value"] = value
                    property["state"] = state
                    properties.append(property)
                device["properties"] = properties
            devices.append(device)
        payload["devices"] = devices
        result["payload"] = payload
        log_request("query", str(req_id), str(a_token) + " ok " + str(result))
        return json.dumps(result)


# noinspection PyShadowingBuiltins,DuplicatedCode
@app.route('/v1.0/user/devices/action', methods=['POST'])
def change_state():
    a_token = request.headers.get("Authorization")
    req_id = request.headers.get("X-Request-Id")
    id = a_token.split("#")[0].split(" ")[1]
    token = a_token.split("#")[1]
    tokens = db["tokens"].find({"_id": id}, {"token": 1})
    valid = False
    for i in tokens:
        valid = check_password_hash(i[0], token)
        if valid:
            break
    if not valid:
        log_request("action", str(req_id), "auth error")
        abort(403)
    else:
        data = json.loads(request.data)
        result = {"request_id": str(req_id)}
        payload = {}
        devices = []
        for i in data["payload"]["devices"]:
            device = {"id": i["id"]}
            type = db["devices"].find_one({"_id": ObjectId(i["id"]), "user_id": id}, {"controller_id": 1, "my_type": 1})
            if type is None:
                device["action_result"] = {"status": "ERROR", "error_code": "DEVICE_NOT_FOUND"}
            else:
                mqtt = db["controllers"].find_one({"_id": ObjectId(type["id"])}, {"mqtt_login": 1, "mqtt_pass": 1,
                                                                                  "mqtt_server": 1, "mqtt_port": 1,
                                                                                  "name": 1, "set_topic": 1})
                topic = mqtt["mqtt_login"] + "/" + mqtt["name"] + "/"
                if mqtt["set_topic"]:
                    topic += "set/"
                capabilities = []
                for j in i["capabilities"]:
                    capability = {"type": j["type"]}
                    state = {}
                    try:
                        if type["my_type"] == "gpio":
                            if j["type"] == "devices.capabilities.on_off":
                                num = db["devices_properties"].find_one({"my_type": "number", "device_id": i["id"]},
                                                                        {"value": 1})["value"]
                                on = db["devices_properties"].find_one({"my_type": "on_state", "device_id": i["id"]},
                                                                       {"value": 1})["value"]
                                state["instance"] = "on"
                                if not j["state"]["value"]:
                                    on = "0" if on == "1" else "1"
                                db["devices_properties"].update_one({"device_id": i["id"], "ya_type":
                                                                     "devices.capabilities.on_off"},
                                                                    {"$set": {"value": j["state"]["value"]}})
                                publish.single(topic + "output" + num, on, hostname=mqtt["mqtt_server"],
                                               port=int(mqtt["mqtt_port"]), auth={"username": mqtt["mqtt_login"],
                                                                                  "password": mqtt["mqtt_pass"]})
                        elif type["my_type"] == "thermo":
                            num = db["devices_properties"].find_one({"my_type": "number", "device_id": i["id"]},
                                                                    {"value": 1})["value"]
                            if j["type"] == "devices.capabilities.range":
                                temper = db["devices_properties"].find_one({"ya_type": "devices.capabilities.range",
                                                                            "device_id": i["id"]}, {"value": 1})["value"
                                                                                                                 ]
                                state["instance"] = "temperature"
                                if j["state"]["relative"]:
                                    temp = str(j["state"]["value"] + float(temper))
                                else:
                                    temp = str(j["state"]["value"])
                                db["devices_properties"].update_one({"ya_type": "devices.capabilities.range",
                                                                     "device_id": i["id"]}, {"$set": {"value": temp}})
                                publish.single(topic + "thermo_set" + num, temp, hostname=mqtt["mqtt_server"],
                                               port=int(mqtt["mqtt_port"]), auth={"username": mqtt["mqtt_login"],
                                                                                  "password": mqtt["mqtt_pass"]})
                            if j["type"] == "devices.capabilities.on_off":
                                state["instance"] = "on"
                                on = "1" if j["state"]["value"] else "0"
                                db["devices_properties"].update_one({"device_id": i["id"], "ya_type":
                                                                     "devices.capabilities.on_off"},
                                                                    {"$set": {"value": j["state"]["value"]}})
                                publish.single(topic + "thermo_en" + num, on, hostname=mqtt["mqtt_server"],
                                               port=int(mqtt["mqtt_port"]), auth={"username": mqtt["mqtt_login"],
                                                                                  "password": mqtt["mqtt_pass"]})
                        elif type["my_type"] == "thermo_gpio":
                            if j["type"] == "devices.capabilities.range":
                                num = db["devices_properties"].find_one({"my_type": "number_t", "device_id": i["id"]},
                                                                        {"value": 1})["value"]
                                temper = db["devices_properties"].find_one({"ya_type": "devices.capabilities.range",
                                                                            "device_id": i["id"]}, {"value": 1})["value"
                                                                                                                 ]
                                state["instance"] = "temperature"
                                if j["state"]["relative"]:
                                    temp = str(j["state"]["value"] + float(temper))
                                else:
                                    temp = str(j["state"]["value"])
                                db["devices_properties"].update_one({"device_id": i["id"], "ya_type":
                                                                     "devices.capabilities.range"},
                                                                    {"$set": {"value": temp}})
                                publish.single(topic + "thermo_set" + num, temp, hostname=mqtt["mqtt_server"],
                                               port=int(mqtt["mqtt_port"]), auth={"username": mqtt["mqtt_login"],
                                                                                  "password": mqtt["mqtt_pass"]})
                            if j["type"] == "devices.capabilities.mode":
                                num_t = db["devices_properties"].find_one({"my_type": "number_t", "device_id": i["id"]},
                                                                          {"value": 1})["value"]
                                num_g = db["devices_properties"].find_one({"my_type": "number_g", "device_id": i["id"]},
                                                                          {"value": 1})["value"]
                                on = db["devices_properties"].find_one({"my_type": "on_state", "device_id": i["id"]},
                                                                       {"value": 1})["value"]
                                state["instance"] = "program"
                                if j["state"]["value"] == "two":
                                    on_t = "0"
                                elif j["state"]["value"] == "one":
                                    on = "0" if on == "1" else "1"
                                    on_t = "0"
                                else:
                                    on = "0" if on == "1" else "1"
                                    on_t = "1"
                                db["devices_properties"].update_one({"device_id": i["id"], "ya_type":
                                                                     "devices.capabilities.mode"},
                                                                    {"$set": {"value": j["state"]["value"]}})
                                publish.single(topic + "output" + num_g, on, hostname=mqtt["mqtt_server"],
                                               port=int(mqtt["mqtt_port"]), auth={"username": mqtt["mqtt_login"],
                                                                                  "password": mqtt["mqtt_pass"]})
                                publish.single(topic + "thermo_en" + num_t, on_t, hostname=mqtt["mqtt_server"],
                                               port=int(mqtt["mqtt_port"]), auth={"username": mqtt["mqtt_login"],
                                                                                  "password": mqtt["mqtt_pass"]})
                    except Exception as e:
                        state["action_result"] = {"status": "ERROR", "error_code": "INTERNAL_ERROR",
                                                  "error_message": str(e)}
                        db.rollback()
                    else:
                        state["action_result"] = {"status": "DONE"}
                    capability["state"] = state
                    capabilities.append(capability)
                device["capabilities"] = capabilities
            devices.append(device)
        payload["devices"] = devices
        result["payload"] = payload
        log_request("action", str(req_id), "ok " + str(result))
        return json.dumps(result)


@app.route('/profile/', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        udata = db["users"].find_one({"_id": ObjectId(current_user.id)})
        if udata["def_mqtt_server"] is not None:
            return render_template("profile.html", server=udata["def_mqtt_server"], port=udata["def_mqtt_port"],
                                   password=udata["def_mqtt_pass"], username=udata["def_mqtt_login"])
        return render_template("profile.html")
    else:
        data = request.form
        if len(data) == 4:
            db["users"].update_one({"_id": ObjectId(current_user.id)},
                                   {"$set": {"def_mqtt_server": data.get('server'), "def_mqtt_port": data.get('port'),
                                    "def_mqtt_pass": data.get('pass'), "def_mqtt_login": data.get('username')}})
            return render_template("profile.html", server=data.get("server"), port=data.get("port"),
                                   password=data.get("pass"), username=data.get("username"),
                                   message="Настройки сохранены")
        elif len(data) == 3:
            password = db["users"].find_one({"_id": ObjectId(current_user.id)})
            udata = db["users"].find_one({"_id": ObjectId(current_user.id)})
            if password is None:
                if udata["def_mqtt_server"] is not None:
                    return render_template("profile.html", server=udata["def_mqtt_server"], port=udata["def_mqtt_port"],
                                           password=udata["def_mqtt_pass"], username=udata["def_mqtt_login"],
                                           message="Ошибка авторизации")
                return render_template("profile.html", message="Ошибка авторизации")
            elif not check_password_hash(password["password"], data.get("old_password")):
                if udata["def_mqtt_server"] is not None:
                    return render_template("profile.html", server=udata["def_mqtt_server"], port=udata["def_mqtt_port"],
                                           password=udata["def_mqtt_pass"], username=udata["def_mqtt_login"],
                                           message="Неверный пароль")
                return render_template("profile.html", message="Неверный пароль")
            else:
                db["users"].update_one({"_id": ObjectId(current_user.id)},
                                       {"$set": {"password": generate_password_hash(data.get("password"))}})
                if udata["def_mqtt_server"] is not None:
                    return render_template("profile.html", server=udata["def_mqtt_server"], port=udata["def_mqtt_port"],
                                           password=udata["def_mqtt_pass"], username=udata["def_mqtt_login"],
                                           message="Пароль сохранен")
                return render_template("profile.html", message="Пароль сохранен")
        else:
            logout_user()
            return redirect(url_for("login"))


@app.route('/controllers/', methods=['GET'])
@login_required
def f_controllers():
    controllers = [list(i.values()) for i in db["controllers"].find({"user_id": current_user.id},
                                                                    {"name": 1, "devices_count": 1})]
    return render_template("devices.html", title="Контроллеры", head=["ID", "Имя", "Количество устройств"],
                           type="controllers", data=controllers, text="Добавить", href="/controllers/",
                           caption="Контроллеры")


@app.route('/controllers/<controller>/delete/', methods=['POST'])
@login_required
def controller_delete(controller):
    user_id = db["controllers"].find_one({"_id": ObjectId(controller)})
    if user_id is None:
        return 'error'
    elif user_id["user_id"] != current_user.id:
        abort(401)
    else:
        db["controllers"].delete_one({"_id": ObjectId(controller)})
        db["devices"].delete_many({"controller_id": controller})
        db["sensors"].delete_many({"controller_id": controller})
        return "ok"


@app.route('/controllers/add/', methods=['POST', 'GET'])
@login_required
def controller_add():
    if request.method == "GET":
        udata = db["users"].find_one({"_id": ObjectId(current_user.id)})
        if udata["def_mqtt_server"] is not None:
            return render_template("add_controller.html", server=udata["def_mqtt_server"], port=udata["def_mqtt_port"],
                                   password=udata["def_mqtt_pass"], username=udata["def_mqtt_login"], set="add")
        return render_template("add_controller.html", set="add")
    else:
        data = request.form
        db["controllers"].insert_one({"user_id": current_user.id, "set_topic": data.get("set_topic") is not None,
                                      "name": data.get("name"), "devices_count": 0, "mqtt_server": data.get("server"),
                                      "mqtt_port": data.get("port"), "mqtt_pass": data.get("pass"),
                                      "mqtt_login": data.get("username")})
        return 'ok'


@app.route('/devices/<device>/delete/', methods=['POST'])
@login_required
def device_delete(device):
    user_id = db["devices"].find_one({"_id": ObjectId(device)})
    if user_id is None:
        return 'error'
    elif user_id["user_id"] != current_user.id:
        abort(401)
    else:
        db["controllers"].update_one({"_id": ObjectId(user_id["controller_id"])},
                                     {"$set": {"devices_count": db["controllers"].find_one(
                                         {"_id": ObjectId(user_id["controller_id"])})["devices_count"] - 1}})
        db["devices"].delete_one({"_id": ObjectId(device)})
        db["devices_properties"].delete_many({"device_id": device})
        db["sensors"].delete_many({"device_id": device})
        return "ok"


@app.route('/controllers/<controller>/', methods=['GET'])
@login_required
def f_controller(controller):
    controll = db["controllers"].find_one({"_id": ObjectId(controller)})
    if controll is None:
        abort(404)
    elif controll["user_id"] != current_user.id:
        abort(401)
    else:
        devices = [list(i.values()) for i in db["devices"].find({"controller_id": controller},
                                                                {"name": 1, "my_type_rus": 1})]
        return render_template("devices.html", title="Устройства", head=["ID", "Имя", "Тип"], type="devices",
                               data=devices, href="/controllers/%s/" % controller, caption=controll["name"])


@app.route('/controllers/<controller>/settings/', methods=['GET', 'POST'])
@login_required
def controller_settings(controller):
    udata = db["controllers"].find_one({"_id": ObjectId(controller)})
    if udata is None:
        abort(404)
    elif udata["user_id"] != current_user.id:
        abort(401)
    else:
        if request.method == "GET":
            if udata is None:
                abort(404)
            return render_template("add_controller.html", set=controller + "/settings", name=udata["name"],
                                   set_topic=udata["set_topic"], server=udata["mqtt_server"], port=udata["mqtt_port"],
                                   password=udata["mqtt_pass"], username=udata["mqtt_login"])
        else:
            data = request.form
            db["controllers"].update_one({"_id": ObjectId(controller)},
                                         {"$set": {"set_topic": data.get("set_topic") is not None, "name":
                                                   data.get("name"), "mqtt_server": data.get("server"),
                                                   "mqtt_port": data.get("port"), "mqtt_pass": data.get("pass"),
                                                   "mqtt_login": data.get("username")}})
            return 'ok'


@app.route('/controllers/<controller>/add/', methods=['GET', 'POST'])
@login_required
def device_add(controller):
    udata = db["controllers"].find_one({"_id": ObjectId(controller)})
    if udata is None:
        abort(404)
    elif udata["user_id"] != current_user.id:
        abort(401)
    else:
        if request.method == "GET":
            return render_template("add_device.html", id=controller)
        else:
            data = request.form
            type_ = data.get("type")
            ya_type = ""
            if type_ == "gpio":
                ru_type = "GPIO"
                ya_type = "devices.types.switch"
                insert = [{
                    "device_id": None,
                    "my_type": "on_state",
                    "value": data.get("on")
                }, {
                    "device_id": None,
                    "my_type": "number",
                    "value": data.get("number")
                }, {
                    "device_id": None,
                    "ya_type": "devices.capabilities.on_off",
                    "instance": "on",
                    "value": False
                }]
            elif type_ == "thermo":
                ru_type = "Термостат"
                ya_type = "devices.types.thermostat"
                insert = [{
                    "device_id": None,
                    "my_type": "number",
                    "value": data.get("number")
                }, {
                    "device_id": None,
                    "ya_type": "devices.capabilities.on_off",
                    "instance": "on",
                    "value": False
                }, {
                    "device_id": None,
                    "ya_type": "devices.capabilities.range",
                    "instance": "temperature",
                    "value": "0"
                }]
            elif type_ == "thermo_gpio":
                insert = [{
                    "device_id": None,
                    "my_type": "on_state",
                    "value": data.get("on")
                }, {
                    "device_id": None,
                    "my_type": "number_t",
                    "value": data.get("number_t")
                }, {
                    "device_id": None,
                    "my_type": "number_g",
                    "value": data.get("number_g")
                }, {
                    "device_id": None,
                    "ya_type": "devices.capabilities.mode",
                    "instance": "program",
                    "value": "one"
                }, {
                    "device_id": None,
                    "ya_type": "devices.capabilities.range",
                    "instance": "temperature",
                    "value": "0"
                }]
                ru_type = "Термостат с поддержкой ручного управления"
                ya_type = "devices.types.thermostat"
            else:
                insert = []
                ru_type = type_
            db["controllers"].update_one({"_id": ObjectId(controller)},
                                         {"$set": {"devices_count": db["controllers"].find_one(
                                             {"_id": ObjectId(controller)})["devices_count"] + 1}})
            id_ = db["devices"].insert_one({"controller_id": controller, "my_type": type_, "name": data.get("name"),
                                           "my_type_rus": ru_type, "user_id": current_user.id, "type": ya_type})
            for i in range(len(insert)):
                insert[i]["device_id"] = str(id_.inserted_id)
            db["devices_properties"].insert_many(insert)
            return 'ok'


@app.route('/controllers/<controller>/<device>/settings/', methods=['GET', 'POST'])
@login_required
def device_settings(controller, device):
    user_id = db["controllers"].find_one({"_id": ObjectId(controller)})
    c_id = db["devices"].find_one({"_id": ObjectId(device)})
    if user_id is None or c_id is None:
        abort(404)
    elif user_id["user_id"] != current_user.id or controller != c_id["controller_id"]:
        abort(401)
    else:
        return "settings"


@app.route('/controllers/<controller>/<device>/<sensor>/', methods=['GET', 'POST'])
@login_required
def sensor_settings(controller, device, sensor):
    user_id = db["controllers"].find_one({"_id": ObjectId(controller)})
    c_id = db["devices"].find_one({"_id": ObjectId(device)})
    s_id = db["sensors"].find_one({"_id": ObjectId(sensor)})
    if user_id is None or c_id is None or s_id is None:
        abort(404)
    elif user_id["user_id"] != current_user.id or controller != str(c_id["controller_id"])\
            or device != s_id["device_id"]:
        abort(401)
    else:
        return "settings"


@app.route('/controllers/<controller>/<device>/add/', methods=['GET', 'POST'])
@login_required
def sensor_add(controller, device):
    user_id = db["controllers"].find_one({"_id": ObjectId(controller)})
    c_id = db["devices"].find_one({"_id": ObjectId(device)})
    if user_id is None or c_id is None:
        abort(404)
    elif user_id["user_id"] != current_user.id or controller != c_id["controller_id"]:
        abort(401)
    else:
        if request.method == "GET":
            r_data = {"amperage": True, "battery_level": True, "co2_level": True, "humidity": True, "power": True,
                      "temperature": True, "voltage": True, "water_level": True}
            for i in db["sensors"].find({"device_id": device}):
                r_data[i["instance"]] = False
            return render_template("add_sensor.html", data=r_data, c_id=controller, d_id=device)
        else:
            data = request.form
            mqtt = db["controllers"].find_one({"_id": ObjectId(controller)})
            rus_type = ""
            if data.get("type") == "amperage":
                rus_type = "Потребление тока"
            elif data.get("type") == "battery_level":
                rus_type = "Уровень заряда аккумулятора"
            elif data.get("type") == "co2_level":
                rus_type = "Уровень углекислого газа"
            elif data.get("type") == "humidity":
                rus_type = "Влажность"
            elif data.get("type") == "power":
                rus_type = "Потребляемая мощность"
            elif data.get("type") == "temperature":
                rus_type = "Температура"
            elif data.get("type") == "voltage":
                rus_type = "Напряжение"
            elif data.get("type") == "water_level":
                rus_type = "Уровень воды"
            topic = mqtt["mqtt_login"] + "/" + mqtt["name"] + "/" + data.get("topic")
            db["sensors"].insert_one({"controller_id": controller, "device_id": device, "user_id": current_user.id,
                                      "value": 0, "instance": data.get("type"), "topic": topic,
                                      "name": data.get("name"), "instance_rus": rus_type})
            return "ok"


@app.route('/sensors/<sensor>/delete/', methods=['POST'])
@login_required
def sensor_delete(sensor):
    user_id = db["sensors"].find_one({"_id": ObjectId(sensor)})
    if user_id is None:
        return 'error'
    elif user_id["user_id"] != current_user.id:
        abort(401)
    else:
        db["sensors"].delete_one({"_id": ObjectId(sensor)})
        return "ok"


@app.route('/controllers/<controller>/<device>/', methods=['GET'])
@login_required
def f_device(controller, device):
    user_id = db["controllers"].find_one({"_id": ObjectId(controller)})
    c_id = db["devices"].find_one({"_id": ObjectId(device)})
    if user_id is None or c_id is None:
        abort(404)
    elif user_id["user_id"] != current_user.id or controller != c_id["controller_id"]:
        abort(401)
    else:
        sensors = [list(i.values()) for i in db["sensors"].find({"device_id": device},
                                                                {"name": 1, "instance_rus": 1})]
        return render_template("devices.html", title="Датчики", head=["ID", "Имя", "Тип"], type="sensors", data=sensors,
                               href="/controllers/%s/%s/" % (controller, device), caption=c_id["name"])


@app.errorhandler(404)
def err404(_):
    return render_template("404.html")


@app.errorhandler(401)
def err401(_):
    return render_template("401.html")


@app.errorhandler(500)
def err500(_):
    return render_template("500.html")


if __name__ == '__main__':
    app.run("0.0.0.0", 5000)
