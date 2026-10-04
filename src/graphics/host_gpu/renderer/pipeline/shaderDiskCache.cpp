#include "graphics/host_gpu/renderer/pipeline/shaderDiskCache.h"

#include "common/assert.h"

#include <cstring>
#include <string>
#include <xxhash.h>

namespace Libs::Graphics {

namespace {

constexpr char     FileMagic[8]     = {'K', 'Y', 'T', 'Y', 'S', 'P', 'V', 'C'};
constexpr uint32_t FileVersion      = 1;
constexpr uint32_t RecordMagic      = 0x52565053u; // "SPVR"
constexpr uint32_t MaxRecordWords   = 16u * 1024u * 1024u;
constexpr uint32_t MaxSignatureSize = 4096;

struct FileHeader {
	char     magic[8];
	uint32_t version;
	uint32_t signature_size;
};

struct RecordHeader {
	uint32_t magic;
	uint32_t word_count;
	uint64_t key_low;
	uint64_t key_high;
	uint64_t fingerprint;
	uint64_t checksum;
};

static_assert(sizeof(FileHeader) == 16);
static_assert(sizeof(RecordHeader) == 40);

uint64_t RecordChecksum(const ShaderDiskCache::Key& key, uint64_t fingerprint,
                        std::span<const uint32_t> words) {
	const uint64_t fields[] = {key.low, key.high, fingerprint, words.size()};
	return XXH3_64bits_withSeed(words.data(), words.size_bytes(),
	                            XXH3_64bits(fields, sizeof(fields)));
}

} // namespace

ShaderDiskCache::KeyBuilder::KeyBuilder(): m_state(XXH3_createState()) {
	EXIT_IF(m_state == nullptr);
	EXIT_IF(XXH3_128bits_reset(m_state) != XXH_OK);
}

ShaderDiskCache::KeyBuilder::~KeyBuilder() {
	XXH3_freeState(m_state);
}

void ShaderDiskCache::KeyBuilder::Add(const void* data, std::size_t size) {
	EXIT_IF(XXH3_128bits_update(m_state, data, size) != XXH_OK);
}

void ShaderDiskCache::KeyBuilder::Add(std::span<const uint32_t> words) {
	Add(static_cast<uint64_t>(words.size()));
	Add(words.data(), words.size_bytes());
}

ShaderDiskCache::Key ShaderDiskCache::KeyBuilder::Finish() const {
	const auto hash = XXH3_128bits_digest(m_state);
	return {.low = hash.low64, .high = hash.high64};
}

std::unique_ptr<ShaderDiskCache> ShaderDiskCache::Open(const std::filesystem::path& path,
                                                       std::string_view             signature) {
	if (signature.size() > MaxSignatureSize) {
		return nullptr;
	}
	if (path.has_parent_path() && !Common::File::CreateDirectories(path.parent_path())) {
		return nullptr;
	}
	std::unique_ptr<ShaderDiskCache> cache(new ShaderDiskCache());
	if (Common::File::IsFileExisting(path) &&
	    cache->m_file.Open(path, Common::File::Mode::ReadWrite)) {
		if (cache->ReadIndex(signature)) {
			return cache;
		}
		cache->m_file.Close();
		cache->m_index.clear();
	}
	if (!cache->m_file.Create(path) || !cache->WriteHeader(signature)) {
		return nullptr;
	}
	return cache;
}

ShaderDiskCache::~ShaderDiskCache() = default;

bool ShaderDiskCache::ReadIndex(std::string_view signature) {
	const auto size = m_file.Size();
	FileHeader header {};
	uint32_t   read = 0;
	if (!m_file.Seek(0)) {
		return false;
	}
	m_file.Read(&header, sizeof(header), &read);
	if (read != sizeof(header) || std::memcmp(header.magic, FileMagic, sizeof(FileMagic)) != 0 ||
	    header.version != FileVersion || header.signature_size != signature.size()) {
		return false;
	}
	std::string stored(signature.size(), '\0');
	read = 0;
	m_file.Read(stored.data(), header.signature_size, &read);
	if (read != signature.size() || stored != signature) {
		return false;
	}

	uint64_t offset = sizeof(header) + signature.size();
	while (size - offset >= sizeof(RecordHeader)) {
		RecordHeader record {};
		read = 0;
		if (!m_file.Seek(offset)) {
			break;
		}
		m_file.Read(&record, sizeof(record), &read);
		if (read != sizeof(record) || record.magic != RecordMagic || record.word_count == 0 ||
		    record.word_count > MaxRecordWords) {
			break;
		}
		const uint64_t bytes = uint64_t {record.word_count} * sizeof(uint32_t);
		if (bytes > size - offset - sizeof(record)) {
			break;
		}
		m_index[{.low = record.key_low, .high = record.key_high}] = {
		    .offset      = offset + sizeof(record),
		    .word_count  = record.word_count,
		    .fingerprint = record.fingerprint,
		    .checksum    = record.checksum,
		};
		offset += sizeof(record) + bytes;
	}
	// Drop a torn or corrupted tail, for example from a crash while a record was written.
	if (offset != size && !m_file.Truncate(offset)) {
		return false;
	}
	m_end = offset;
	return true;
}

bool ShaderDiskCache::WriteHeader(std::string_view signature) {
	FileHeader header {};
	std::memcpy(header.magic, FileMagic, sizeof(FileMagic));
	header.version             = FileVersion;
	header.signature_size      = static_cast<uint32_t>(signature.size());
	uint32_t header_written    = 0;
	uint32_t signature_written = 0;
	m_file.Write(&header, sizeof(header), &header_written);
	if (!signature.empty()) {
		m_file.Write(signature.data(), header.signature_size, &signature_written);
	}
	if (header_written != sizeof(header) || signature_written != signature.size()) {
		return false;
	}
	m_end = sizeof(header) + signature.size();
	return true;
}

bool ShaderDiskCache::Load(const Key& key, uint64_t fingerprint, std::vector<uint32_t>& spirv) {
	const auto iter = m_index.find(key);
	if (iter == m_index.end() || iter->second.fingerprint != fingerprint) {
		return false;
	}
	const auto&           entry = iter->second;
	std::vector<uint32_t> words(entry.word_count);
	uint32_t              read = 0;
	if (m_file.Seek(entry.offset)) {
		m_file.Read(words.data(), static_cast<uint32_t>(words.size() * sizeof(uint32_t)), &read);
	}
	if (read != words.size() * sizeof(uint32_t) ||
	    RecordChecksum(key, fingerprint, words) != entry.checksum) {
		m_index.erase(iter);
		return false;
	}
	spirv = std::move(words);
	return true;
}

void ShaderDiskCache::Store(const Key& key, uint64_t fingerprint, std::span<const uint32_t> spirv) {
	if (m_failed || spirv.empty() || spirv.size() > MaxRecordWords) {
		return;
	}
	const RecordHeader record {
	    .magic       = RecordMagic,
	    .word_count  = static_cast<uint32_t>(spirv.size()),
	    .key_low     = key.low,
	    .key_high    = key.high,
	    .fingerprint = fingerprint,
	    .checksum    = RecordChecksum(key, fingerprint, spirv),
	};
	uint32_t record_written  = 0;
	uint32_t payload_written = 0;
	if (m_file.Seek(m_end)) {
		m_file.Write(&record, sizeof(record), &record_written);
		m_file.Write(spirv.data(), static_cast<uint32_t>(spirv.size_bytes()), &payload_written);
	}
	if (record_written != sizeof(record) || payload_written != spirv.size_bytes()) {
		// For example a full disk. The next start drops the torn record.
		m_failed = true;
		return;
	}
	m_index[key] = {
	    .offset      = m_end + sizeof(record),
	    .word_count  = record.word_count,
	    .fingerprint = fingerprint,
	    .checksum    = record.checksum,
	};
	m_end += sizeof(record) + spirv.size_bytes();
}

} // namespace Libs::Graphics
