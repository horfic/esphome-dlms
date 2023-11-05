#pragma once

#include "esphome/core/component.h"
#include "esphome/components/uart/uart.h"

namespace esphome {
  namespace dlms {
      //enum DataLinkLayer { DATA_LINK_LAYER_HDLC = 'hdlc', DATA_LINK_LAYER_MBUS = 'mbus' };

      const uint8_t HDLC_FRAME_FLAG = 0x7e;
      const uint8_t HDLC_FRAME_FORMAT_TYPE_3 = 0xa0;

      class Dlms : public Component, public uart::UARTDevice {
        public:
          void setup() override;
          void loop() override;
          void dump_config() override;

          void set_decryption_key(const std::string &decryption_key);
          void set_auth_key(const std::string &auth_key);
          void set_data_link_layer(const std::string &data_link_layer);
        protected:
          void reset_dll_frame();
          void decrypt_dlms_data(uint8_t *dlms_data, size_t data_size);
          std::vector<uint8_t> decryption_key_{};
          std::vector<uint8_t> auth_key_{};
          std::string data_link_layer_;
          uint8_t *dll_frame_{nullptr};
          size_t dll_frame_length_{0};
          size_t bytes_read_{0};
      };
  }  // namespace dsmr
}  // namespace esphome