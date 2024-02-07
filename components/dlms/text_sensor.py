import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import text_sensor

from . import Dlms, CONF_DLMS_ID

AUTO_LOAD = ["dlms"]

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_DLMS_ID): cv.use_id(Dlms),
        cv.Optional("manufacturer"): text_sensor.text_sensor_schema(),
        cv.Optional("serial_number"): text_sensor.text_sensor_schema(),
        cv.Optional("device_type"): text_sensor.text_sensor_schema(),
        cv.Optional("timestamp"): text_sensor.text_sensor_schema(),
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    hub = await cg.get_variable(config[CONF_DLMS_ID])

    text_sensors = []
    for key, conf in config.items():
        if not isinstance(conf, dict):
            continue
        id = conf.get("id")
        if id and id.type == text_sensor.TextSensor:
            var = await text_sensor.new_text_sensor(conf)
            cg.add(getattr(hub, f"set_{key}")(var))
            text_sensors.append(f"F({key})")

    if text_sensors:
        cg.add_define(
            "DLMS_TEXT_SENSOR_LIST(F, sep)",
            cg.RawExpression(" sep ".join(text_sensors)),
        )