#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <map>
namespace SQLite {
    class SQLiteHandler {
    public:
        SQLiteHandler(std::string dbPath);
        bool ReadTable(std::string tableName);
        int GetRowCount() { return (int)_tableEntries.size(); }
        std::vector<std::string> GetFieldNames() { return _fieldNames; }
        std::string GetValue(int rowNum, std::string fieldName) {
            if (rowNum >= 0 && rowNum < (int)_tableEntries.size()) {
                auto it = _tableEntries[rowNum].find(fieldName);
                if (it != _tableEntries[rowNum].end()) return it->second;
            }
            return "";
        }
        std::string GetValue(int rowNum, int fieldIdx) {
            if (rowNum >= 0 && rowNum < (int)_tableEntries.size()) {
                std::string key = (fieldIdx < (int)_fieldNames.size())
                    ? _fieldNames[fieldIdx]
                    : "field_" + std::to_string(fieldIdx);
                auto it = _tableEntries[rowNum].find(key);
                if (it != _tableEntries[rowNum].end()) return it->second;
            }
            return "";
        }
    private:
        std::string _dbPath;
        size_t _fileSize;
        std::vector<uint8_t> _fileBytes;
        std::vector<std::string> _fieldNames;
        std::vector<std::map<std::string, std::string>> _tableEntries;
        // depth: prevents infinite recursion on corrupt/cyclic page chains
        void ParsePage(int pageNum, uint16_t pageSize, bool isMaster, int depth = 0);
        void ParseCell(size_t offset, uint16_t pageSize, size_t pageBase, bool isMaster);
        int  ReadVarint(size_t offset, uint64_t& value);
        int  ReadVarint2(const std::vector<uint8_t>& buf, size_t offset, uint64_t& value);
        void ParseFieldsFromSql(std::string sql);
    };
}
