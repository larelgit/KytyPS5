#include "common/common.h"
#include "graphics/host_gpu/renderer/pipeline/shaderDiskCache.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using Libs::Graphics::ShaderDiskCache;

void Check(bool value, const char *text) {
  if (!value) {
    std::fprintf(stderr, "ShaderDiskCacheTests: failed: %s\n", text);
    std::abort();
  }
}

class TempDirectory {
public:
  TempDirectory() {
    const auto unique =
        std::chrono::steady_clock::now().time_since_epoch().count();
    m_path = std::filesystem::temp_directory_path() /
             ("kyty_shader_cache_test_" + std::to_string(unique));
    Check(std::filesystem::create_directories(m_path),
          "create temporary directory");
  }

  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(m_path, error);
  }

  [[nodiscard]] const std::filesystem::path &Path() const { return m_path; }

  KYTY_CLASS_NO_COPY(TempDirectory);

private:
  std::filesystem::path m_path;
};

ShaderDiskCache::Key MakeKey(uint32_t value) {
  ShaderDiskCache::KeyBuilder builder;
  builder.Add(value);
  return builder.Finish();
}

std::vector<uint32_t> MakeModule(uint32_t seed, uint32_t words) {
  std::vector<uint32_t> module(words);
  for (uint32_t i = 0; i < words; i++) {
    module[i] = seed * 0x9e3779b9u + i;
  }
  return module;
}

bool Loads(ShaderDiskCache &cache, const ShaderDiskCache::Key &key,
           uint64_t fingerprint, const std::vector<uint32_t> &expected) {
  std::vector<uint32_t> loaded;
  return cache.Load(key, fingerprint, loaded) && loaded == expected;
}

void FlipByte(const std::filesystem::path &path, std::streamoff offset) {
  std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
  Check(file.good(), "open cache file for corruption");
  file.seekg(offset);
  char value = 0;
  file.read(&value, 1);
  value = static_cast<char>(value ^ 0x5a);
  file.seekp(offset);
  file.write(&value, 1);
}

void TestKeyBuilder() {
  const auto key = [](auto &&...parts) {
    ShaderDiskCache::KeyBuilder builder;
    (builder.Add(parts), ...);
    return builder.Finish();
  };
  const std::vector<uint32_t> abc = {1, 2, 3};
  const std::vector<uint32_t> ab = {1, 2};
  const std::vector<uint32_t> bc = {2, 3};
  const std::vector<uint32_t> a = {1};
  const std::vector<uint32_t> c = {3};
  Check(key(std::span<const uint32_t>(abc), 7u) ==
            key(std::span<const uint32_t>(abc), 7u),
        "equal inputs produced different keys");
  Check(key(std::span<const uint32_t>(abc), 7u) !=
            key(std::span<const uint32_t>(abc), 8u),
        "different inputs produced the same key");
  Check(key(std::span<const uint32_t>(ab), std::span<const uint32_t>(c)) !=
            key(std::span<const uint32_t>(a), std::span<const uint32_t>(bc)),
        "differently split word spans produced the same key");
}

void TestRoundTrip() {
  TempDirectory directory;
  const auto path = directory.Path() / "cache" / "TITLE00000.bin";
  const auto first = MakeModule(1, 100);
  const auto second = MakeModule(2, 1);
  const auto third = MakeModule(3, 5000);
  {
    auto cache = ShaderDiskCache::Open(path, "signature-a");
    Check(cache != nullptr && cache->EntryCount() == 0,
          "a new cache was not empty");
    cache->Store(MakeKey(1), 11, first);
    cache->Store(MakeKey(2), 22, second);
    cache->Store(MakeKey(3), 33, third);
    Check(Loads(*cache, MakeKey(1), 11, first) &&
              Loads(*cache, MakeKey(2), 22, second) &&
              Loads(*cache, MakeKey(3), 33, third),
          "stored modules did not load in the same session");
    std::vector<uint32_t> unused;
    Check(!cache->Load(MakeKey(1), 12, unused),
          "a module loaded with another interface fingerprint");
    Check(!cache->Load(MakeKey(4), 11, unused), "an unknown key loaded");
  }
  {
    auto cache = ShaderDiskCache::Open(path, "signature-a");
    Check(cache != nullptr && cache->EntryCount() == 3,
          "reopening did not find the stored modules");
    Check(Loads(*cache, MakeKey(1), 11, first) &&
              Loads(*cache, MakeKey(2), 22, second) &&
              Loads(*cache, MakeKey(3), 33, third),
          "stored modules did not load after reopening");
  }
  {
    auto cache = ShaderDiskCache::Open(path, "signature-b");
    Check(cache != nullptr && cache->EntryCount() == 0,
          "a cache from another emulator revision was not discarded");
    std::vector<uint32_t> unused;
    Check(!cache->Load(MakeKey(1), 11, unused),
          "a module from another emulator revision loaded");
    cache->Store(MakeKey(5), 55, first);
  }
  {
    auto cache = ShaderDiskCache::Open(path, "signature-b");
    Check(cache != nullptr && cache->EntryCount() == 1 &&
              Loads(*cache, MakeKey(5), 55, first),
          "a module stored after a signature change did not persist");
  }
}

void TestTornTail() {
  TempDirectory directory;
  const auto path = directory.Path() / "TITLE00000.bin";
  const auto first = MakeModule(1, 64);
  const auto second = MakeModule(2, 64);
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    cache->Store(MakeKey(1), 1, first);
    cache->Store(MakeKey(2), 2, second);
  }
  const auto complete_size = std::filesystem::file_size(path);
  {
    // A record header announcing more words than follow, as after a crash.
    std::ofstream file(path, std::ios::binary | std::ios::app);
    const uint32_t torn[] = {0x52565053u, 1000u, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    file.write(reinterpret_cast<const char *>(torn), sizeof(torn));
  }
  const auto third = MakeModule(3, 32);
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    Check(cache != nullptr && cache->EntryCount() == 2,
          "a torn record changed the intact entries");
    Check(std::filesystem::file_size(path) == complete_size,
          "the torn record was not truncated");
    Check(Loads(*cache, MakeKey(1), 1, first) &&
              Loads(*cache, MakeKey(2), 2, second),
          "intact modules did not load after a torn record");
    cache->Store(MakeKey(3), 3, third);
  }
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    Check(cache != nullptr && cache->EntryCount() == 3 &&
              Loads(*cache, MakeKey(3), 3, third),
          "a module stored after truncation did not persist");
  }
}

void TestCorruptedPayload() {
  TempDirectory directory;
  const auto path = directory.Path() / "TITLE00000.bin";
  const auto first = MakeModule(1, 64);
  const auto second = MakeModule(2, 64);
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    cache->Store(MakeKey(1), 1, first);
    cache->Store(MakeKey(2), 2, second);
  }
  // The file header is 16 bytes plus the signature; a record header is 40.
  constexpr std::streamoff FirstPayload = 16 + 9 + 40;
  FlipByte(path, FirstPayload + 17);
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    Check(cache != nullptr, "a cache with a corrupted payload did not open");
    std::vector<uint32_t> unused;
    Check(!cache->Load(MakeKey(1), 1, unused),
          "a module with a corrupted payload loaded");
    Check(Loads(*cache, MakeKey(2), 2, second),
          "corruption in one record broke another");
    cache->Store(MakeKey(1), 1, first);
    Check(Loads(*cache, MakeKey(1), 1, first),
          "a rewritten module did not load");
  }
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    Check(Loads(*cache, MakeKey(1), 1, first),
          "the latest record for a key did not win after reopening");
  }
  {
    // A corrupted file header discards the whole file.
    FlipByte(path, 2);
    auto cache = ShaderDiskCache::Open(path, "signature");
    Check(cache != nullptr && cache->EntryCount() == 0,
          "a cache with a corrupted header was not discarded");
  }
}

void TestFingerprintReplacement() {
  TempDirectory directory;
  const auto path = directory.Path() / "TITLE00000.bin";
  const auto old_module = MakeModule(1, 16);
  const auto new_module = MakeModule(2, 24);
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    cache->Store(MakeKey(1), 1, old_module);
    cache->Store(MakeKey(1), 2, new_module);
    std::vector<uint32_t> unused;
    Check(!cache->Load(MakeKey(1), 1, unused) &&
              Loads(*cache, MakeKey(1), 2, new_module),
          "a replaced module did not supersede the old one");
  }
  {
    auto cache = ShaderDiskCache::Open(path, "signature");
    std::vector<uint32_t> unused;
    Check(cache->EntryCount() == 1 && !cache->Load(MakeKey(1), 1, unused) &&
              Loads(*cache, MakeKey(1), 2, new_module),
          "the replacement did not survive reopening");
  }
}

} // namespace

int main() {
  TestKeyBuilder();
  TestRoundTrip();
  TestTornTail();
  TestCorruptedPayload();
  TestFingerprintReplacement();
  std::puts("ShaderDiskCacheTests: all cases passed");
  return 0;
}
