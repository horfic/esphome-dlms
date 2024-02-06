import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import sensor
from esphome.const import (
    CONF_ID,
    DEVICE_CLASS_POWER,
    DEVICE_CLASS_ENERGY,
    STATE_CLASS_MEASUREMENT,
    STATE_CLASS_TOTAL_INCREASING,
    UNIT_KILOWATT,
    UNIT_KILOWATT_HOURS,
    UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
    UNIT_KILOVOLT_AMPS_REACTIVE,
)
from . import Dlms, CONF_DLMS_ID

AUTO_LOAD = ["dlms"]


CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_DLMS_ID): cv.use_id(Dlms),
        cv.Optional("positive_active_energy_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT_HOURS,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_ENERGY,
            state_class=STATE_CLASS_TOTAL_INCREASING,
        ),
        cv.Optional("positive_active_energy_tariff1"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT_HOURS,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_ENERGY,
            state_class=STATE_CLASS_TOTAL_INCREASING,
        ),
        cv.Optional("positive_active_energy_tariff2"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT_HOURS,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_ENERGY,
            state_class=STATE_CLASS_TOTAL_INCREASING,
        ),
        cv.Optional("positive_active_instant_power_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_POWER,
            state_class=STATE_CLASS_MEASUREMENT,
        ),
        cv.Optional("negative_active_energy_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT_HOURS,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_ENERGY,
            state_class=STATE_CLASS_TOTAL_INCREASING,
        ),
        cv.Optional("negative_active_energy_tariff1"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT_HOURS,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_ENERGY,
            state_class=STATE_CLASS_TOTAL_INCREASING,
        ),
        cv.Optional("negative_active_energy_tariff2"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT_HOURS,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_ENERGY,
            state_class=STATE_CLASS_TOTAL_INCREASING,
        ),
        cv.Optional("negative_active_instant_power_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOWATT,
            accuracy_decimals=3,
            device_class=DEVICE_CLASS_POWER,
            state_class=STATE_CLASS_MEASUREMENT,
        ),
        cv.Optional("positive_reactive_energy_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
            accuracy_decimals=3,
        ),
        cv.Optional("positive_reactive_energy_tariff1"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
            accuracy_decimals=3,
        ),
        cv.Optional("positive_reactive_energy_tariff2"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
            accuracy_decimals=3,
        ),
        cv.Optional("positive_reactive_instant_power_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE,
            accuracy_decimals=3,
            state_class=STATE_CLASS_MEASUREMENT,
        ),
        cv.Optional("negative_reactive_energy_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
            accuracy_decimals=3,
        ),
        cv.Optional("negative_reactive_energy_tariff1"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
            accuracy_decimals=3,
        ),
        cv.Optional("negative_reactive_energy_tariff2"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE_HOURS,
            accuracy_decimals=3,
        ),
        cv.Optional("negative_reactive_instant_power_total"): sensor.sensor_schema(
            unit_of_measurement=UNIT_KILOVOLT_AMPS_REACTIVE,
            accuracy_decimals=3,
            state_class=STATE_CLASS_MEASUREMENT,
        ),

    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    hub = await cg.get_variable(config[CONF_DLMS_ID])

    sensors = []
    for key, conf in config.items():
        if not isinstance(conf, dict):
            continue
        id = conf[CONF_ID]
        if id and id.type == sensor.Sensor:
            sens = await sensor.new_sensor(conf)
            cg.add(getattr(hub, f"set_{key}")(sens))
            sensors.append(f"F({key})")

    if sensors:
        cg.add_define(
            "DLMS_SENSOR_LIST(F, sep)", cg.RawExpression(" sep ".join(sensors))
        )