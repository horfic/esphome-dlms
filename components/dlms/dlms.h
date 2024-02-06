#pragma once

#include "esphome/core/component.h"
#include "esphome/components/uart/uart.h"

namespace esphome {
  namespace dlms {
      const uint8_t HDLC_FRAME_FLAG = 0x7e;
      const uint8_t HDLC_FRAME_FORMAT_TYPE_3 = 0xa0;
      const uint8_t GCM_START_FLAG = 0xdb;

      #define HDLC_CRC16_ORDER 16
      #define HDLC_CRC16_POLYNOM 0x1021
      #define HDLC_CRC16_INIT 0xffff
      #define HDLC_CRC16_XOR 0xffff

      #ifndef DSMR_SENSOR_LIST
      #define DSMR_SENSOR_LIST(F, SEP)
      #endif

      #ifndef DSMR_TEXT_SENSOR_LIST
      #define DSMR_TEXT_SENSOR_LIST(F, SEP)
      #endif

      class Dlms : public Component, public uart::UARTDevice {
        public:
          void setup() override;
          void loop() override;
          void dump_config() override;

          void set_decryption_key(const std::string &decryption_key);
          void set_auth_key(const std::string &auth_key);
          void set_data_link_layer(const std::string &data_link_layer);

          // Auto generate sensor setters
          #define DLMS_SET_SENSOR(s) \
            void set_##s(sensor::Sensor *sensor) { s_##s##_ = sensor; }
            DLMS_SENSOR_LIST(DLMS_SET_SENSOR, )

          #define DLMS_SET_TEXT_SENSOR(s) \
            void set_##s(text_sensor::TextSensor *sensor) { s_##s##_ = sensor; }
            DLMS_TEXT_SENSOR_LIST(DLMS_SET_TEXT_SENSOR, )

        protected:
          void reset_apdu();
          void reset_frame();
          void decrypt_dlms_data(uint8_t *dlms_data);
          bool crc16_check(uint8_t *data, size_t size);

          uint16_t crc16_bit_by_bit(unsigned char *p, uint16_t len);
          uint16_t crc16_reflect(uint16_t crc, int bitnum);

          std::vector<uint8_t> decryption_key_{};
          std::vector<uint8_t> auth_key_{};
          std::string data_link_layer_;

          uint8_t *frame_buffer_{nullptr};
          size_t frames_read_{0};
          size_t frame_length_{0};
          size_t frame_bytes_read_{0};

          uint8_t *apdu_buffer_{nullptr};
          size_t apdu_length_{0};
          size_t apdu_bytes_read_{0};
          size_t apdu_offset_{0};

          // Auto generate sensor member pointers
          #define DLMS_DECLARE_SENSOR(s) sensor::Sensor *s_##s##_{nullptr};
            DLMS_SENSOR_LIST(DLMS_DECLARE_SENSOR, )

          #define DLMS_DECLARE_TEXT_SENSOR(s) text_sensor::TextSensor *s_##s##_{nullptr};
            DLMS_TEXT_SENSOR_LIST(DLMS_DECLARE_TEXT_SENSOR, )
      };
  }  // namespace dsmr
}  // namespace esphome