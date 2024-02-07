#include "dlms.h"
#include "esphome/core/log.h"
#include "esphome/core/helpers.h"

#include <AES.h>
#include <Crypto.h>
#include <GCM.h>

namespace esphome {
  namespace dlms {
    static const char *const TAG = "dlms";

    void Dlms::setup() {
      this->reset_apdu();
      this->reset_frame();
    }

    // ToDo - implement max hdlc frame size of 250?? and max pdu size of 2030??, configurable timeout (11 sec) and buffer size (2048)
    void Dlms::loop() {
      while (this->available()) {
        const char c = this->read();

        // Check if first byte is actually the end byte of the last frame
        if (this->frame_bytes_read_ == 1 && (uint8_t) c == HDLC_FRAME_FLAG) {
          ESP_LOGD(TAG, "Started reading from end flag, skipping...");

          continue;
        }

        // Check if frame format type 3 is used
        if (this->frame_bytes_read_ == 1 && (uint8_t) c != HDLC_FRAME_FORMAT_TYPE_3) {
          ESP_LOGD(TAG, "HDLC frame format type is not supported, resetting...");

          this->reset_frame();
          continue;
        }

        // Check if gcm flag is found for frame 1
        if (this->frames_read_ == 0 && this->frame_bytes_read_ == 19) {
          if ((uint8_t) c != GCM_START_FLAG) {
            ESP_LOGD(TAG, "GCM Flag not found in first frame, resetting...");

            this->reset_frame();
            this->reset_apdu();
            continue;
          } else {
            this->apdu_offset_ = 20;
            this->frames_read_ = 1;
          }
        }

        // Check if frame length is not exceeded
        if ( this->frame_bytes_read_ > 2 && this->frame_bytes_read_ > this->frame_length_) {
          ESP_LOGW(TAG, "Received more bytes as frame length, resetting...");

          this->reset_frame();
          continue;
        }

        // Validating HDLC header
        if (this->frame_bytes_read_ == 9) {
          bool is_valid_header = this->crc16_check(&this->frame_buffer_[1], 8);

          if (!is_valid_header) {
            ESP_LOGW(TAG, "HDLC header validation failed, resetting...");

            this->reset_frame();
            continue;
          }
        }

        // Start HDLC frame reading
        if (this->frame_bytes_read_ == 0 && (uint8_t) c == HDLC_FRAME_FLAG) {
          ESP_LOGD(TAG, "HDLC frame found");

          this->frame_buffer_[this->frame_bytes_read_] = c;
          this->frame_bytes_read_++;

          if (this->frames_read_ != 0) {
            this->frames_read_++;
          }
          continue;
        }

        // Set frame length with start and end flag
        if (this->frame_bytes_read_ == 2) {
          this->frame_length_ = (unsigned) c + 2;

          ESP_LOGD(TAG, "Frame length found %i", this->frame_length_);
        }

        // Set apdu length
        if (this->frames_read_ == 1 && this->frame_bytes_read_ == 32) {
          this->apdu_length_ = (unsigned) ((this->frame_buffer_[30] << 8) | this->frame_buffer_[31]);
          this->apdu_length_ += 12;

          ESP_LOGD(TAG, "APDU length found %i", this->apdu_length_);
        }

        // Continue hdlc frame building
        if (this->frame_bytes_read_ > 0) {
          ESP_LOGV(TAG, "Saving HDLC frame byte");

          this->frame_buffer_[this->frame_bytes_read_] = c;
          this->frame_bytes_read_++;
        }

        // ToDo - Read source and destination address, maximum length 4 or 5? do check (currentByte & 0x01) == 0

        // Reading last byte of frame
        if (this->frame_bytes_read_ != 0 && this->frame_bytes_read_ == this->frame_length_ && (uint8_t) c == HDLC_FRAME_FLAG) {
          // ToDo - calculate destination and source address lengths https://github.com/alekslt/HANToMQTT/blob/master/DlmsReader.cpp#L436

          // Validating hdlc frame
          bool is_valid_frame = this->crc16_check(&this->frame_buffer_[1], this->frame_bytes_read_ -2);
          if (!is_valid_frame) {
            ESP_LOGW(TAG, "HDLC frame validation failed, resetting...");

            this->reset_frame();
            continue;
          }

          ESP_LOGD(TAG, "Frames read %i", this->frames_read_);
          ESP_LOGD(TAG, "APDU offset %i", this->apdu_offset_);
          ESP_LOGD(TAG, "APDU length %i", this->apdu_length_);
          ESP_LOGD(TAG, "Frame : %s", format_hex_pretty(this->frame_buffer_, this->frame_length_).c_str());

          size_t apdu_part_length = this->frame_length_ - this->apdu_offset_ - 3;

          memcpy(&this->apdu_buffer_[this->apdu_bytes_read_], &this->frame_buffer_[this->apdu_offset_], apdu_part_length);

          this->apdu_bytes_read_ += apdu_part_length;

          if (this->apdu_length_ < this->apdu_bytes_read_) {
            this->reset_apdu();
          }

          if (this->apdu_length_ == this->apdu_bytes_read_) {
            ESP_LOGD(TAG, "APDU : %s", format_hex_pretty(this->apdu_buffer_, this->apdu_length_).c_str());

            // Decrypt apdu
            this->decrypt_dlms_data(&this->apdu_buffer_[0]);

            this->reset_apdu();
          }

          this->reset_frame();
        }
      }
    }

    void Dlms::dump_config() {
      ESP_LOGCONFIG(TAG, "DLMS:");
    }

    void Dlms::reset_apdu() {
      this->apdu_length_ = 0;
      this->apdu_bytes_read_ = 0;
      this->frames_read_ = 0;

      delete[] this->apdu_buffer_;
      this->apdu_buffer_ = new uint8_t[2030];
    }

    void Dlms::reset_frame() {
      delete[] this->frame_buffer_;
      this->frame_buffer_ = new uint8_t[250];

      this->frame_bytes_read_ = 0;
      this->frame_length_ = 0;
      this->apdu_offset_ = 16;
    }

    void Dlms::decrypt_dlms_data(uint8_t *apdu) {
      ESP_LOGV(TAG, "Decrypting payload");

      uint8_t iv[12];

      //Get dynamic the system title length byte and read the system title bytes into iv
      memcpy(&iv[0], &apdu[1], apdu[0]);

      //INFO: Nonce wird bei jedem Paket um 1 größer (=increment counter)
      //Get dynamic the nonce (frame counter bytes), length is probably static with 4 bytes and read into iv
      memcpy(&iv[8], &apdu[13], 4);

      ESP_LOGD(TAG, "GCM IV : %s", format_hex_pretty(iv, 12).c_str());

      GCM<AESSmall128> aes;
      aes.setIV(iv, 12);

      uint8_t *decryption_key = this->decryption_key_.data();
      aes.setKey(decryption_key, 16);
        ESP_LOGD(TAG, "GCM Decryption Key : %s", format_hex_pretty(decryption_key, 16).c_str());

      //Only enable auth when auth key is set, possible check also with security byte is 0x30, 0x50 and 0x70 to force enable it and throw an error?
      if (!this->auth_key_.empty()) {
        uint8_t *auth_key = new uint8_t[17];
        memcpy(&auth_key[0], &apdu[12], 1);
        memcpy(&auth_key[1], &this->auth_key_[0], 16);

        ESP_LOGD(TAG, "GCM AUTH Key : %s", format_hex_pretty(auth_key, 17).c_str());
        aes.addAuthData(auth_key, 17);
      }

      uint8_t sml_data[2030];

      //Get dynamic start of cipher text content, byte after the frame counter (nonce), also get dynamic length of the cipher text content
      aes.decrypt(sml_data, &apdu[17], this->apdu_length_ - 17);

      uint8_t tag[12];
      //Get 12 bytes gcm tag dynamic from the end of the frame
      memcpy(&tag[0], &apdu[this->apdu_length_ - 12], 12);
      ESP_LOGD(TAG, "GCM TAG : %s", format_hex_pretty(tag, 12).c_str());

      if (!aes.checkTag(tag, sizeof(tag))) {
        ESP_LOGE(TAG, "Decryption failed");
      } else {
        ESP_LOGW(TAG, "Decryption successful");
      }

      ESP_LOGD(TAG, "Crypt data: %s", format_hex_pretty(&apdu[17], this->apdu_length_ - 17).c_str());
      ESP_LOGD(TAG, "Decrypted data: %s", format_hex_pretty(sml_data, sizeof(sml_data)).c_str());

      if (this->s_manufacturer_ != nullptr) {
        char manufacturer_string [3];
        sprintf(manufacturer_string, "%c%c%c", iv[0], iv[1], iv[2]);
        this->s_manufacturer_->publish_state(manufacturer_string);
      }

      // Mapping
      uint16_t Year;
      uint8_t Month;
      uint8_t Day;
      uint8_t Hour;
      uint8_t Minute;
      uint8_t Second;
      uint32_t positive_active_energy_total;
      uint32_t positive_active_energy_tariff1;
      uint32_t positive_active_energy_tariff2;
      uint32_t positive_active_instant_power_total;
      uint32_t negative_active_energy_total;
      uint32_t negative_active_energy_tariff1;
      uint32_t negative_active_energy_tariff2;
      uint32_t negative_active_instant_power_total;
      uint32_t positive_reactive_energy_total;
      uint32_t positive_reactive_energy_tariff1;
      uint32_t positive_reactive_energy_tariff2;
      uint32_t positive_reactive_instant_power_total;
      uint32_t negative_reactive_energy_total;
      uint32_t negative_reactive_energy_tariff1;
      uint32_t negative_reactive_energy_tariff2;
      uint32_t negative_reactive_instant_power_total;

      Year = sml_data[22] << 8 | sml_data[23];
      Month = sml_data[24];
      Day = sml_data[25];
      Hour = sml_data[27];
      Minute = sml_data[28];
      Second = sml_data[29];
      //ESP_LOGI(TAG, "SML Data timestamp: %i-%i-%iT%i:%i:%iZ", Year, Month, Day, Hour, Minute, Second);

      if (this->s_timestamp_ != nullptr) {
        //char timestamp_string [20];
        //sprintf(timestamp_string, "%i-%02d-%02dT%02d:%02d:%02dZ", Year, Month, Day, Hour, Minute, Second);
        //this->s_timestamp_->publish_state(timestamp_string);
      }

      positive_active_energy_total = sml_data[43] << 24 | sml_data[44] << 16 | sml_data[45] << 8 | sml_data[46]; // [Wh]
      ESP_LOGI(TAG, "SML Data 1.8.0: %0.3fkWh", (size_t) positive_active_energy_total / 1000.00);

      if (this->s_positive_active_energy_total_ != nullptr) {
        this->s_positive_active_energy_total_->publish_state((size_t) positive_active_energy_total / 1000.00);
      }

      positive_active_energy_tariff1  = sml_data[56] << 24 | sml_data[57] << 16 | sml_data[58] << 8 | sml_data[59]; // [Wh]
      ESP_LOGI(TAG, "SML Data 1.8.1: %0.3fkWh", (size_t) positive_active_energy_tariff1 / 1000.00);

      if (this->s_positive_active_energy_tariff1_ != nullptr) {
        this->s_positive_active_energy_tariff1_->publish_state((size_t) positive_active_energy_tariff1 / 1000.00);
      }

      positive_active_energy_tariff2 = sml_data[69] << 24 | sml_data[70] << 16 | sml_data[71] << 8 | sml_data[72]; // [Wh]
      ESP_LOGI(TAG, "SML Data 1.8.2: %0.3fkWh", (size_t) positive_active_energy_tariff2 / 1000.00);

      if (this->s_positive_active_energy_tariff2_ != nullptr) {
        this->s_positive_active_energy_tariff2_->publish_state((size_t) positive_active_energy_tariff2 / 1000.00);
      }

      positive_active_instant_power_total = sml_data[82] << 24 | sml_data[83] << 16 | sml_data[84] << 8 | sml_data[85]; // [W]
      ESP_LOGI(TAG, "SML Data 1.7.0: %0.3fkW", (size_t) positive_active_instant_power_total / 1000.00);

      if (this->s_positive_active_instant_power_total_ != nullptr) {
        this->s_positive_active_instant_power_total_->publish_state((size_t) positive_active_instant_power_total / 1000.00);
      }

      negative_active_energy_total = sml_data[95] << 24 | sml_data[96] << 16 | sml_data[97] << 8 | sml_data[98]; // [Wh]
      ESP_LOGI(TAG, "SML Data 2.8.0: %0.3fkWh", (size_t) negative_active_energy_total / 1000.00);

      if (this->s_negative_active_energy_total_ != nullptr) {
        this->s_negative_active_energy_total_->publish_state((size_t) negative_active_energy_total / 1000.00);
      }

      negative_active_energy_tariff1  = sml_data[108] << 24 | sml_data[109] << 16 | sml_data[110] << 8 | sml_data[111]; // [Wh]
      ESP_LOGI(TAG, "SML Data 2.8.1: %0.3fkWh", (size_t) negative_active_energy_tariff1 / 1000.00);

      if (this->s_negative_active_energy_tariff1_ != nullptr) {
        this->s_negative_active_energy_tariff1_->publish_state((size_t) negative_active_energy_tariff1 / 1000.00);
      }

      negative_active_energy_tariff2 = sml_data[121] << 24 | sml_data[122] << 16 | sml_data[123] << 8 | sml_data[124]; // [Wh]
      ESP_LOGI(TAG, "SML Data 2.8.2: %0.3fkWh", (size_t) negative_active_energy_tariff2 / 1000.00);

      if (this->s_negative_active_energy_tariff2_ != nullptr) {
        this->s_negative_active_energy_tariff2_->publish_state((size_t) negative_active_energy_tariff2 / 1000.00);
      }

      negative_active_instant_power_total = sml_data[134] << 24 | sml_data[135] << 16 | sml_data[136] << 8 | sml_data[137]; // [W]
      ESP_LOGI(TAG, "SML Data 2.7.0: %0.3fkW", (size_t) negative_active_instant_power_total / 1000.00);

      if (this->s_negative_active_instant_power_total_ != nullptr) {
        this->s_negative_active_instant_power_total_->publish_state((size_t) negative_active_instant_power_total / 1000.00);
      }

      positive_reactive_energy_total = sml_data[147] << 24 | sml_data[148] << 16 | sml_data[149] << 8 | sml_data[150]; // [VArh]
      ESP_LOGI(TAG, "SML Data 3.8.0: %0.3fkVArh", (size_t) positive_reactive_energy_total / 1000.00);

      if (this->s_positive_reactive_energy_total_ != nullptr) {
        this->s_positive_reactive_energy_total_->publish_state((size_t) positive_reactive_energy_total / 1000.00);
      }

      positive_reactive_energy_tariff1  = sml_data[160] << 24 | sml_data[161] << 16 | sml_data[162] << 8 | sml_data[163]; // [VArh]
      ESP_LOGI(TAG, "SML Data 3.8.1: %0.3fkVArh", (size_t) positive_reactive_energy_tariff1 / 1000.00);

      if (this->s_positive_reactive_energy_tariff1_ != nullptr) {
        this->s_positive_reactive_energy_tariff1_->publish_state((size_t) positive_reactive_energy_tariff1 / 1000.00);
      }

      positive_reactive_energy_tariff2 = sml_data[173] << 24 | sml_data[174] << 16 | sml_data[175] << 8 | sml_data[176]; // [VArh]
      ESP_LOGI(TAG, "SML Data 3.8.2: %0.3fkVArh", (size_t) positive_reactive_energy_tariff2 / 1000.00);

      if (this->s_positive_reactive_energy_tariff2_ != nullptr) {
        this->s_positive_reactive_energy_tariff2_->publish_state((size_t) positive_reactive_energy_tariff2 / 1000.00);
      }

      positive_reactive_instant_power_total = sml_data[186] << 24 | sml_data[187] << 16 | sml_data[188] << 8 | sml_data[189]; // [VAr]
      ESP_LOGI(TAG, "SML Data 3.7.0: %0.3fkVAr", (size_t) positive_reactive_instant_power_total / 1000.00);

      if (this->s_positive_reactive_instant_power_total_ != nullptr) {
        this->s_positive_reactive_instant_power_total_->publish_state((size_t) positive_reactive_instant_power_total / 1000.00);
      }

      negative_reactive_energy_total = sml_data[199] << 24 | sml_data[200] << 16 | sml_data[201] << 8 | sml_data[202]; // [VArh]
      ESP_LOGI(TAG, "SML Data 4.8.0: %0.3fkVArh", (size_t) negative_reactive_energy_total / 1000.00);

      if (this->s_negative_reactive_energy_total_ != nullptr) {
        this->s_negative_reactive_energy_total_->publish_state((size_t) negative_reactive_energy_total / 1000.00);
      }

      negative_reactive_energy_tariff1  = sml_data[212] << 24 | sml_data[213] << 16 | sml_data[214] << 8 | sml_data[215]; // [VArh]
      ESP_LOGI(TAG, "SML Data 4.8.1: %0.3fkVArh", (size_t) negative_reactive_energy_tariff1 / 1000.00);

      if (this->s_negative_reactive_energy_tariff1_ != nullptr) {
        this->s_negative_reactive_energy_tariff1_->publish_state((size_t) negative_reactive_energy_tariff1 / 1000.00);
      }

      negative_reactive_energy_tariff2 = sml_data[225] << 24 | sml_data[226] << 16 | sml_data[227] << 8 | sml_data[228]; // [VArh]
      ESP_LOGI(TAG, "SML Data 4.8.2: %0.3fkVArh", (size_t) negative_reactive_energy_tariff2 / 1000.00);

      if (this->s_negative_reactive_energy_tariff2_ != nullptr) {
        this->s_negative_reactive_energy_tariff2_->publish_state((size_t) negative_reactive_energy_tariff2 / 1000.00);
      }

      negative_reactive_instant_power_total = sml_data[238] << 24 | sml_data[239] << 16 | sml_data[240] << 8 | sml_data[241]; // [VAr]
      ESP_LOGI(TAG, "SML Data 4.7.0: %0.3fkVAr", (size_t) negative_reactive_instant_power_total / 1000.00);

      if (this->s_negative_reactive_instant_power_total_ != nullptr) {
        this->s_negative_reactive_instant_power_total_->publish_state((size_t) negative_reactive_instant_power_total / 1000.00);
      }
    }

    bool Dlms::crc16_check(uint8_t *data, size_t data_size) {
      uint16_t crc = this->crc16_bit_by_bit(data, data_size - 2); // -2 because last 2 bytes are the checksum I have to compare it to
      uint8_t hi_byte = (crc & 0xff00) >> 8;
      uint8_t lo_byte = (crc & 0xff);

      return hi_byte == data[data_size - 1] && lo_byte == data[data_size - 2];
    }

    // http://www.zorc.breitbandkatze.de/crc.html
    // http://www.zorc.breitbandkatze.de/crctester.c
    uint16_t Dlms::crc16_bit_by_bit(unsigned char *p, uint16_t len) {
      uint16_t crchighbit;
      uint16_t i, j, c, bit, crc;
      uint16_t crcmask;

      crcmask = ((((uint16_t)1 << (HDLC_CRC16_ORDER - 1)) - 1) << 1) | 1;
      crchighbit = (uint16_t)1 << (HDLC_CRC16_ORDER - 1);

      crc = HDLC_CRC16_INIT;
      for (i = 0; i < HDLC_CRC16_ORDER; i++) {
        bit = crc & 1;
        if (bit) {
          crc ^= HDLC_CRC16_POLYNOM;
        }

        crc >>= 1;
        if (bit) {
          crc |= crchighbit;
        }
      }

      // bit by bit algorithm with augmented zero bytes.
      // does not use lookup table, suited for polynom orders between 1...32.

      for (i = 0; i < len; i++) {
        c = (uint16_t)*p++;
        c = this->crc16_reflect(c, 8);

        for (j = 0x80; j; j >>= 1) {
          bit = crc & crchighbit;
          crc <<= 1;
          if (c & j) {
              crc |= 1;
          }

          if (bit) {
            crc ^= HDLC_CRC16_POLYNOM;
          }
        }
      }

      for (i = 0; i < HDLC_CRC16_ORDER; i++) {
        bit = crc & crchighbit;
        crc <<= 1;
        if (bit) {
          crc ^= HDLC_CRC16_POLYNOM;
        }
      }

      crc = this->crc16_reflect(crc, HDLC_CRC16_ORDER);
      crc ^= HDLC_CRC16_XOR;
      crc &= crcmask;

      return (crc);
    }

    uint16_t Dlms::crc16_reflect(uint16_t crc, int bitnum) {
      // reflects the lower 'bitnum' bits of 'crc'

      uint16_t i, j = 1, crcout = 0;

      for (i = (uint16_t)1 << (bitnum - 1); i; i >>= 1) {
        if (crc & i) {
          crcout |= j;
        }
        j <<= 1;
      }

      return (crcout);
    }

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
