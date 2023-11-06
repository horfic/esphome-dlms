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
      this->reset_dll_frame();
    }

    // ToDo - implement configurable timeout (11 sec) and buffer size (2048)
    void Dlms::loop() {
      while (this->available()) {
        const char c = this->read();

        // We started to read the end flag, so we got the start flag again, can skip one
        //if (this->bytes_read_ == 1 && (uint8_t) c == HDLC_FRAME_FLAG && this->dll_frame_length_ == 0) {
        //  ESP_LOGD(TAG, "found frame flag again, second time, skipping");

        //  this->reset_dll_frame();
        //  continue;
        //}

        // Check if frame format type 3 is used
        if (this->bytes_read_ == 1 && (uint8_t) c != HDLC_FRAME_FORMAT_TYPE_3) {
          ESP_LOGD(TAG, "HDLC frame format type is not supported");

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
          ESP_LOGD(TAG, "Frame length found %i", (unsigned) c + 2);
          this->dll_frame_length_ = (unsigned) c + 2;
        }

        // Start hdlc frame building
        if (this->bytes_read_ == 0 && (uint8_t) c == HDLC_FRAME_FLAG) {
          ESP_LOGV(TAG, "HDLC frame found");

          this->dll_frame_[this->bytes_read_] = c;
          this->bytes_read_++;
          continue;
        }

        // Continue hdlc frame building
        if (this->bytes_read_ > 0) {
          ESP_LOGV(TAG, "saving hdlc frame byte");

          this->dll_frame_[this->bytes_read_] = c;
          this->bytes_read_++;
        }

        // ToDo - Read source and destination address, maximum length 4 or 5? do check (currentByte & 0x01) == 0

        // End of hdlc frame building
        if (this->bytes_read_ != 0 && this->bytes_read_ == this->dll_frame_length_ && (uint8_t) c == HDLC_FRAME_FLAG) {
          //ToDo - calculate destionan and source address lengths https://github.com/alekslt/HANToMQTT/blob/master/DlmsReader.cpp#L436
          //Without hdlc flags, header = frame type + frame length + destionation address + source address length + checksum byte
          bool is_valid_header = this->crc16_check(&this->dll_frame_[1], 8);
          ESP_LOGD(TAG, "HDLC Header Checksum result: %i", is_valid_header);

          //Without hdlc flags
          bool is_valid_frame = this->crc16_check(&this->dll_frame_[1], this->bytes_read_ -2);
          ESP_LOGD(TAG, "HDLC Frame Checksum result: %i", is_valid_frame);

          //Output frame with flags
          ESP_LOGD(TAG, "HDLC Frame : %s", format_hex_pretty(this->dll_frame_, this->dll_frame_length_).c_str());

          //Decrypt dlms data
          this->decrypt_dlms_data(&this->dll_frame_[0]);

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

    void Dlms::decrypt_dlms_data(uint8_t *dll_frame) {
      ESP_LOGV(TAG, "Decrypting payload");

      uint8_t iv[12];

      //Get dynamic the system title length byte and read the system title bytes into iv
      memcpy(&iv[0], &dll_frame[21], dll_frame[20]);

      //INFO: Nonce wird bei jedem Paket um 1 größer (=increment counter)
      //Get dynamic the nonce (frame counter bytes), length is probably static with 4 bytes and read into iv
      memcpy(&iv[8], &dll_frame[33], 4);

      ESP_LOGD(TAG, "GCM IV : %s", format_hex_pretty(iv, 12).c_str());

      GCM<AESSmall128> aes;
      aes.setIV(iv, sizeof(iv));

      uint8_t *decryption_key = this->decryption_key_.data();
      aes.setKey(decryption_key, 16);
        ESP_LOGD(TAG, "GCM Decryption Key : %s", format_hex_pretty(decryption_key, 16).c_str());

      //Only enable auth when auth key is set, possible check also with security byte is 0x30? 0x20 seams to only tell to do encryption
      if (!this->auth_key_.empty()) {
        uint8_t *auth_key = new uint8_t[17];
        memcpy(&auth_key[0], &dll_frame[32], 1);
        memcpy(&auth_key[1], &this->auth_key_[0], 16);

        ESP_LOGD(TAG, "GCM AUTH Key : %s", format_hex_pretty(auth_key, 17).c_str());
        aes.addAuthData(auth_key, 17);
      }

      //What size to set, 88? based on 38 start byte to end of cipher 126 (141 - end flag - 2x crc checksum - 12x gcm tag)
      uint8_t sml_data[512];

      //Get dynamic start of cipher text content, byte after the frame counter (nonce), also get dynamic length of the cipher text content
      aes.decrypt(sml_data, &dll_frame[37], 89);

      uint8_t tag[12];
      //Get 12 bytes gcm tag dynamic from the end of the frame
      memcpy(&tag[0], &dll_frame[126], sizeof(tag));
      ESP_LOGD(TAG, "GCM TAG : %s", format_hex_pretty(tag, 12).c_str());

      if (!aes.checkTag(tag, sizeof(tag))) {
        ESP_LOGE(TAG, "Decryption failed");
      } else {
        ESP_LOGW(TAG, "Decryption successful");
      }

      ESP_LOGD(TAG, "Crypt data: %s", format_hex_pretty(&dll_frame[37], 101).c_str());
      ESP_LOGD(TAG, "Encrypted data: %s", format_hex_pretty(sml_data, sizeof(sml_data)).c_str());

      // Gelesene Werte
      uint16_t Year;
      uint8_t Month;
      uint8_t Day;
      uint8_t Hour;
      uint8_t Minute;
      uint8_t Second;
      uint16_t L1Voltage;
      uint16_t L2Voltage;
      uint16_t L3Voltage;
      uint16_t L1Current;
      uint16_t L2Current;
      uint16_t L3Current;
      uint32_t ImportPower;
      uint32_t ExportPower;
      uint32_t TotalEnergyConsumed;
      uint32_t TotalEnergyConsumedTarif1;
      uint32_t TotalEnergyConsumedTarif2;
      uint32_t TotalEnergyExported;

      Year = sml_data[22] << 8 | sml_data[23];
      Month = sml_data[24];
      Day = sml_data[25];
      Hour = sml_data[27];
      Minute = sml_data[28];
      Second = sml_data[29];
      ESP_LOGI(TAG, "SML Data DateTime: %i-%i-%i %i:%i:%i", Year, Month, Day, Hour, Minute, Second);

//      L1Voltage = sml_data[21] << 8 | sml_data[22]; // [V]
//      L2Voltage = sml_data[24] << 8 | sml_data[25]; // [V]
//      L3Voltage = sml_data[27] << 8 | sml_data[28]; // [V]
//      ESP_LOGD(TAG, "SML Data voltage: L1 %i L2 %i L3 %i", L1Voltage, L2Voltage, L3Voltage);
//
//      L1Current = sml_data[30] << 8 | sml_data[31]; // [cA]
//      L2Current = sml_data[33] << 8 | sml_data[34]; // [cA]
//      L3Current = sml_data[36] << 8 | sml_data[37]; // [cA]
//      ESP_LOGD(TAG, "SML Data current: L1 %i L2 %i L3 %i", L1Current, L2Current, L3Current);
//
//      ImportPower = sml_data[39] << 24 | sml_data[40] << 16 | sml_data[41] << 8 | sml_data[42]; // [W]
//      ESP_LOGD(TAG, "SML Data import power: %i", ImportPower);
//      ExportPower = sml_data[44] << 24 | sml_data[45] << 16 | sml_data[46] << 8 | sml_data[47]; // [W]
//      ESP_LOGD(TAG, "SML Data export power: %i", ExportPower);

      TotalEnergyConsumed = (sml_data[44] << 16 | sml_data[45] << 8 | sml_data[46]) / 1000; // [KWh]
      ESP_LOGI(TAG, "SML Data TotalEnergyConsumed: %i", TotalEnergyConsumed);

      TotalEnergyConsumedTarif1 = (sml_data[57] << 16 | sml_data[58] << 8 | sml_data[59]) / 1000; // [KWh]
      ESP_LOGI(TAG, "SML Data TotalEnergyConsumedTarif1: %i", TotalEnergyConsumedTarif1);

      TotalEnergyConsumedTarif2 = (sml_data[70] << 16 | sml_data[71] << 8 | sml_data[72]) / 1000; // [KWh]
      ESP_LOGI(TAG, "SML Data TotalEnergyConsumedTarif2: %i", TotalEnergyConsumedTarif2);

//      ExportEnergy = sml_data[54] << 24 | sml_data[55] << 16 | sml_data[56] << 8 | sml_data[57]; // [Wh]
//      ESP_LOGD(TAG, "SML Data export energy: %i", ExportEnergy);
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
