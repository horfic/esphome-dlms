#include "dlms.h"
#include "esphome/core/log.h"
#include "esphome/core/helpers.h"

namespace esphome {
  namespace dlms {
    static const char *const TAG = "dlms";

    void Dlms::setup() {
      this->reset_dll_frame();
    }

    // ToDo - implement configurable timeout (11 sec) and buffer size (2048)
    void Dlms::loop() {
      while (this->available()) {
        const char c = this->read();

        ESP_LOGD(TAG, "byte read: %s", (std::string) c)
        ESP_LOGD(TAG, "byte read count: %i", this->bytes_read_)

        // We started to read the end flag, so we got the start flag again, can skip one
        if (this->bytes_read_ == 1 && (uint8_t) c == HDLC_FRAME_FLAG) {
          continue;
        }

        // Check if frame format type 3 is used
        if (this->bytes_read_ == 1 && (uint8_t) c != HDLC_FRAME_FORMAT_TYPE_3) {
          ESP_LOGV(TAG, "HDLC frame format type is not supported");

          this->reset_dll_frame();
          continue;
        }

        if ( this->bytes_read_ > 2 && this->bytes_read_ > this->dll_frame_length_) {
          ESP_LOGW(TAG, "Received more bytes as frame length, resetting");

          this->reset_dll_frame();
          continue;
        }

        // Set data length with start and end flag
        if (this->bytes_read_ == 2) {
          this->dll_frame_length_ = (unsigned) c + 2;
        }

        // Start hdlc frame building
        if (this->bytes_read_ == 0 && (uint8_t) c == HDLC_FRAME_FLAG) {
          ESP_LOGV(TAG, "HDLC frame found");

          this->dll_frame_[this->bytes_read_] = c;
          this->bytes_read_++;
        }

        // Continue hdlc frame building
        if (this->bytes_read_ > 0) {
          this->dll_frame_[this->bytes_read_] = c;
          this->bytes_read_++;
        }

        // ToDo - Read source and destination address, maximum length 4 or 5? do check (currentByte & 0x01) == 0

        // End of hdlc frame building
        if (this->bytes_read_ > 1 && (uint8_t) c == HDLC_FRAME_FLAG) {
          this->dll_frame_[this->bytes_read_] = c;
          this->bytes_read_++;

          ESP_LOGD(TAG, "hdlc frame full: %s", format_hex_pretty(this->dll_frame_, sizeof(this->dll_frame_)).c_str());

          //ToDo - crc16 check for header (hcs) and frame (fcs) https://github.com/alekslt/HANToMQTT/blob/master/DlmsReader.cpp#L276
          //this->decrypt_dlms_data(&this->dll_frame_[0], this->bytes_read_);

          this->reset_dll_frame();
        }
      }
    }

    void Dlms::dump_config() {
      ESP_LOGCONFIG(TAG, "DLMS:");
    }

    void Dlms::reset_dll_frame() {
      delete[] this->dll_frame_;
      this->dll_frame_ = new uint8_t[512];

      this->bytes_read_ = 0;
      this->dll_frame_length_ = 0;
    }

//    void Dlms::decrypt_dlms_data(uint8_t *dll_frame, size_t data_size) {
//      ESP_LOGV(TAG, "Decrypting payload");
//
//      uint8_t iv[12];
//
//      // 8 Bytes von 13 (=system-title)
//      // Add 1 to the offset in order to skip the system title length byte
//      memcpy(&iv[0], &dll_frame[DLMS_SYST_OFFSET + 1], systitleLength);
//
//      // 4 Bytes von 23 (=nonce). INFO: Nonce wird bei jedem Paket um 1 größer (=increment counter)
//      memcpy(&iv[8], &dll_frame[headerOffset + DLMS_FRAMECOUNTER_OFFSET], DLMS_FRAMECOUNTER_LENGTH);
//
//      // Erstes Byte (vor dem Authentication Key) ist Byte 22 (=security byte)
//      this->auth_key_[0] = dll_frame[LandisHDCLHeaderSize + 10];
//
//      uint8_t tag[12];
//      // 12 Bytes ab Index 95
//      memcpy(&tag[0], &dll_frame[LandisHDCLHeaderSize + 83], sizeof(tag));
//
//      uint8_t sml_data[this->dll_frame_length_];
//
//      GCM<AESSmall128> aes;
//      aes.setKey(this->decryption_key_, sizeof(this->decryption_key_));
//      aes.setIV(iv, sizeof(iv));
//
//      //ToDo - Add security byte to the beginning
//      aes.addAuthData(this->auth_key_, sizeof(this->auth_key_));
//
//      // Ciphertext ist ab Index 27
//      aes.decrypt(sml_data, &dll_frame[headerOffset + DLMS_PAYLOAD_OFFSET], this->dll_frame_length_);
//      if (!aes.checkTag(tag, sizeof(tag))) {
//        ESP_LOGE(TAG, "Decryption failed");
//        return;
//      }
//
//      ESP_LOGD(TAG, "RX: %s", format_hex_pretty(sml_data, sizeof(sml_data)).c_str());
//    }

    void Dlms::set_decryption_key(const std::string &decryption_key) {
      if (decryption_key.length() == 0) {
        ESP_LOGI(TAG, "Disabling decryption");
        this->decryption_key_.clear();
        return;
      }

      if (decryption_key.length() != 32) {
        ESP_LOGE(TAG, "Error, decryption key must be 32 character long");
        return;
      }
      this->decryption_key_.clear();

      ESP_LOGI(TAG, "Decryption key is set");
      // Verbose level prints decryption key
      ESP_LOGV(TAG, "Using decryption key: %s", decryption_key.c_str());

      char temp[3] = {0};
      for (int i = 0; i < 16; i++) {
        strncpy(temp, &(decryption_key.c_str()[i * 2]), 2);
        this->decryption_key_.push_back(std::strtoul(temp, nullptr, 16));
      }
    }

    void Dlms::set_auth_key(const std::string &auth_key) {
      if (auth_key.length() == 0) {
        ESP_LOGI(TAG, "Disabling auth");
        this->auth_key_.clear();
        return;
      }

      if (auth_key.length() != 32) {
        ESP_LOGE(TAG, "Error, auth key must be 32 character long");
        return;
      }
      this->auth_key_.clear();

      ESP_LOGI(TAG, "Auth key is set");
      // Verbose level prints auth key
      ESP_LOGV(TAG, "Using auth key: %s", auth_key.c_str());

      char temp[3] = {0};
      for (int i = 0; i < 16; i++) {
        strncpy(temp, &(auth_key.c_str()[i * 2]), 2);
        this->auth_key_.push_back(std::strtoul(temp, nullptr, 16));
      }
    }

    void Dlms::set_data_link_layer(const std::string &data_link_layer) {
      if (data_link_layer != "hdlc") {
        ESP_LOGE(TAG, "Error, data link layer is not supported");
        return;
      }

      this->data_link_layer_ = data_link_layer;
    }
  }
}
