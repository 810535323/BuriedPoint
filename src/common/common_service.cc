#include "common/common_service.h"

#ifdef _WIN32
#include <windows.h>
#elif __linux__
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <fstream>
#include <unistd.h>
#include <cstring>
#endif

#include <algorithm>
#include <chrono>
#include <ctime>
#include <random>

#include "buried_config.h"

namespace buried {

CommonService::CommonService() { Init(); }
#ifdef _WIN32
static void WriteRegister(const std::string& key, const std::string& value) {
  HKEY h_key;
  LONG ret = ::RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Buried", 0, NULL,
                               REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                               &h_key, NULL);
  if (ret != ERROR_SUCCESS) {
    return;
  }
  ret = ::RegSetValueExA(h_key, key.c_str(), 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(value.c_str()),
                         value.size());
  if (ret != ERROR_SUCCESS) {
    return;
  }
  ::RegCloseKey(h_key);
}

static std::string ReadRegister(const std::string& key) {
  HKEY h_key;
  LONG ret = ::RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Buried", 0,
                             KEY_ALL_ACCESS, &h_key);
  if (ret != ERROR_SUCCESS) {
    return "";
  }
  char buf[1024] = {0};
  DWORD buf_size = sizeof(buf);
  ret = ::RegQueryValueExA(h_key, key.c_str(), NULL, NULL,
                           reinterpret_cast<BYTE*>(buf), &buf_size);
  if (ret != ERROR_SUCCESS) {
    return "";
  }
  ::RegCloseKey(h_key);
  return buf;
}
#endif

static std::string GetDeviceId() {
  #ifdef _WIN32
    // Windows-specific code
    static constexpr auto kDeviceIdKey = "device_id";
    static std::string device_id = ReadRegister(kDeviceIdKey);
    if (device_id.empty()) {
      device_id = CommonService::GetRandomId();
      WriteRegister(kDeviceIdKey, device_id);
    }
    return device_id;
  #elif __linux__
    // Linux-specific code
    std::ifstream file("/etc/machine-id");
    std::string device_id;
    std::getline(file, device_id);
    return device_id;
  #else
    // Return empty string for other OS
    return "";
  #endif
}

static std::string GetLifeCycleId() {
  static std::string life_cycle_id = CommonService::GetRandomId();
  return life_cycle_id;
}

static std::string GetSystemVersion() {
  #ifdef _WIN32
    // Windows-specific code
    OSVERSIONINFOEXA os_version_info;
    ZeroMemory(&os_version_info, sizeof(OSVERSIONINFOEXA));
    os_version_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    ::GetVersionExA(reinterpret_cast<OSVERSIONINFOA*>(&os_version_info));
    std::string system_version =
        std::to_string(os_version_info.dwMajorVersion) + "." +
        std::to_string(os_version_info.dwMinorVersion) + "." +
        std::to_string(os_version_info.dwBuildNumber);
    return system_version;
  #elif __linux__
    // Linux-specific code
    struct utsname buffer;
    if (uname(&buffer) != 0) {
        return "";  // error occurred
    }
    return buffer.release;
  #else
    // Return empty string for other OS
    return "";
  #endif
}

static std::string GetDeviceName() {
  #ifdef _WIN32
    // Windows-specific code
    char buf[1024] = {0};
    DWORD buf_size = sizeof(buf);
    ::GetComputerNameA(buf, &buf_size);
    std::string device_name = buf;
    return device_name;
  #elif __linux__
    // Linux-specific code
    char name[1024];
    if (gethostname(name, sizeof(name)) != 0) {
        return std::strerror(errno);  // Return the error message if gethostname fails
    }
    return name;
  #else
    // Return empty string for other OS
    return "";
  #endif
}

std::string CommonService::GetProcessTime() {
  char buf[128] = {0};
#ifdef _WIN32
	// Windows-specific code
	DWORD pid = ::GetCurrentProcessId();
	HANDLE h_process =
      ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (h_process == NULL) {
		return "";
	}
	FILETIME create_time;
	FILETIME exit_time;
	FILETIME kernel_time;
	FILETIME user_time;
	BOOL ret = ::GetProcessTimes(h_process, &create_time, &exit_time,
                               &kernel_time, &user_time);
	::CloseHandle(h_process);
	if (ret == 0) {
		return "";
	}

	FILETIME create_local_time;
	::FileTimeToLocalFileTime(&create_time, &create_local_time);

	SYSTEMTIME create_sys_time;
	::FileTimeToSystemTime(&create_local_time, &create_sys_time);
	
	// year month day hour minute second millisecond
	sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d", create_sys_time.wYear,
            create_sys_time.wMonth, create_sys_time.wDay, create_sys_time.wHour,
            create_sys_time.wMinute, create_sys_time.wSecond,
            create_sys_time.wMilliseconds);
#elif __linux__
  // Linux-specific code
  struct sysinfo si;
  sysinfo(&si);
  clock_t t = times(NULL);
  long ticks_per_second = sysconf(_SC_CLK_TCK);
  time_t process_uptime = t / ticks_per_second;  // process uptime in seconds
  time_t boot_time = si.uptime - process_uptime; // system boot time
  time_t process_start_time = boot_time + process_uptime;

  std::tm* ptm = std::localtime(&process_start_time);

  sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", 
            ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday, 
            ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
#else
  return ""; // return empty string for other OS
#endif

    return buf;
}

std::string CommonService::GetNowDate() {
  auto t =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  return std::ctime(&t);
}

std::string CommonService::GetRandomId() {
  static constexpr size_t len = 32;
  static constexpr auto chars =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  static std::mt19937_64 rng{std::random_device{}()};
  static std::uniform_int_distribution<size_t> dist{0, 60};
  std::string result;
  result.reserve(len);
  std::generate_n(std::back_inserter(result), len,
                  [&]() { return chars[dist(rng)]; });
  return result;
}

void CommonService::Init() {
  system_version = GetSystemVersion();
  device_name = GetDeviceName();
  device_id = GetDeviceId();
  buried_version = PROJECT_VER;
  lifecycle_id = GetLifeCycleId();
}

}  // namespace buried
