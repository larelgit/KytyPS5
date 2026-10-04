#ifndef EMULATOR_SRC_GRAPHICS_HOST_GPU_RENDERER_PIPELINE_SHADERDISKCACHE_H_
#define EMULATOR_SRC_GRAPHICS_HOST_GPU_RENDERER_PIPELINE_SHADERDISKCACHE_H_

#include "common/common.h"
#include "common/file.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

struct XXH3_state_s;

namespace Libs::Graphics {

// Append-only file of SPIR-V modules keyed by a 128-bit hash of everything the shader
// recompiler consumed for them. Every record carries a checksum over its key, fingerprint and
// words, so a torn or corrupted record is never loaded. The whole file is discarded when its
// signature (format and emulator revision) differs. Not thread-safe.
class ShaderDiskCache {
public:
	struct Key {
		uint64_t low  = 0;
		uint64_t high = 0;

		bool operator==(const Key&) const = default;
	};

	class KeyBuilder {
	public:
		KeyBuilder();
		~KeyBuilder();
		KYTY_CLASS_NO_COPY(KeyBuilder);

		void Add(const void* data, std::size_t size);
		void Add(uint32_t value) { Add(&value, sizeof(value)); }
		void Add(uint64_t value) { Add(&value, sizeof(value)); }
		// Adds the word count and then the words, so adjacent spans cannot alias.
		void Add(std::span<const uint32_t> words);

		[[nodiscard]] Key Finish() const;

	private:
		XXH3_state_s* m_state = nullptr;
	};

	// Opens the cache at path, or starts an empty one when the file is missing, unreadable or
	// was written with another signature. Returns nullptr when the file cannot be created.
	static std::unique_ptr<ShaderDiskCache> Open(const std::filesystem::path& path,
	                                             std::string_view             signature);

	~ShaderDiskCache();
	KYTY_CLASS_NO_COPY(ShaderDiskCache);

	// Fills spirv and returns true when a valid record for key was stored with the same
	// interface fingerprint.
	bool Load(const Key& key, uint64_t fingerprint, std::vector<uint32_t>& spirv);
	// Appends a record; a later record for the same key replaces earlier ones.
	void Store(const Key& key, uint64_t fingerprint, std::span<const uint32_t> spirv);

	[[nodiscard]] std::size_t EntryCount() const noexcept { return m_index.size(); }

private:
	struct Entry {
		uint64_t offset      = 0;
		uint32_t word_count  = 0;
		uint64_t fingerprint = 0;
		uint64_t checksum    = 0;
	};

	struct KeyHash {
		std::size_t operator()(const Key& key) const noexcept {
			return static_cast<std::size_t>(key.low ^ (key.high * 0x9e3779b97f4a7c15ull));
		}
	};

	ShaderDiskCache() = default;

	bool ReadIndex(std::string_view signature);
	bool WriteHeader(std::string_view signature);

	Common::File                            m_file;
	uint64_t                                m_end    = 0;
	bool                                    m_failed = false;
	std::unordered_map<Key, Entry, KeyHash> m_index;
};

} // namespace Libs::Graphics

#endif // EMULATOR_SRC_GRAPHICS_HOST_GPU_RENDERER_PIPELINE_SHADERDISKCACHE_H_
