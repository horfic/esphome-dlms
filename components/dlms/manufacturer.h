#pragma once

#include <map>
#include <string>

namespace esphome {
  namespace dlms {
    const std::map <std::string, std::string> manufacturers {
      {"LGZ", "Landis+Gyr AG"},
      {"SAG", "Sagemcom Energy & Telecom"}
    };
  }
}