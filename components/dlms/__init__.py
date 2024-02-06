import esphome.config_validation as cv
import esphome.codegen as cg
from esphome.components import uart
from esphome.const import CONF_ID

CODEOWNERS = ["@horfic"]

MULTI_CONF = True

DEPENDENCIES = ["uart"]

AUTO_LOAD = ["sensor", "text_sensor"]

CONF_DLMS_ID = "dlms_id"
CONF_DATA_LINK_LAYER = "data_link_layer"
CONF_DECRYPTION_KEY = 'decryption_key'
CONF_AUTH_KEY = 'auth_key'

dlms_ns = cg.esphome_ns.namespace("dlms")
Dlms = dlms_ns.class_(
    "Dlms", cg.Component, uart.UARTDevice
)


def _validate_key(value):
    value = cv.string_strict(value)
    parts = [value[i : i + 2] for i in range(0, len(value), 2)]
    if len(parts) != 16:
        raise cv.Invalid("Decryption key must consist of 16 hexadecimal numbers")
    parts_int = []
    if any(len(part) != 2 for part in parts):
        raise cv.Invalid("Decryption key must be format XX")
    for part in parts:
        try:
            parts_int.append(int(part, 16))
        except ValueError:
            # pylint: disable=raise-missing-from
            raise cv.Invalid("Decryption key must be hex values from 00 to FF")

    return "".join(f"{part:02X}" for part in parts_int)


def _validate_data_link_layer(value):
    data_link_layer_supported = ["hdlc"]
    if value not in data_link_layer_supported:
        raise cv.Invalid(f"Data Link layer {value} is not supported. Use one of {data_link_layer_supported}")

    return value


CONFIG_SCHEMA = cv.All(
    cv.Schema({
        cv.GenerateID(): cv.declare_id(Dlms),
        cv.Optional(CONF_DECRYPTION_KEY, default=""): _validate_key,
        cv.Optional(CONF_AUTH_KEY, default=""): _validate_key,
        cv.Optional(CONF_DATA_LINK_LAYER, default="hdlc"): _validate_data_link_layer,
    }).extend(uart.UART_DEVICE_SCHEMA),
    cv.only_with_arduino,
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    cg.add(var.set_decryption_key(config[CONF_DECRYPTION_KEY]))
    cg.add(var.set_data_link_layer(config[CONF_DATA_LINK_LAYER]))

    if CONF_AUTH_KEY in config:
        cg.add(var.set_auth_key(config[CONF_AUTH_KEY]))

    await cg.register_component(var, config)
    await uart.register_uart_device(var, config)

    # Crypto
    cg.add_library("rweather/Crypto", "0.4.0")
