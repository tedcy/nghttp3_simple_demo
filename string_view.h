#pragma once
#include <cstring>
#include <string>
#include <stdexcept>
#include <iostream>

class MyStringView {
private:
    const char* data_; // 原始字符串的指针，只用于引用
    size_t size_;      // 长度
public:
    // 默认构造函数
    MyStringView() : data_(nullptr), size_(0) {}

    // 从 c-string 构造
    MyStringView(const char* str) : data_(str), size_(std::strlen(str)) {}

    // 从字符串指针和长度构造
    MyStringView(const char* str, size_t len) : data_(str), size_(len) {}

    MyStringView(const std::string& str)
        : data_(str.data()), size_(str.size()) {}

    // 获取字符串的开始指针
    const char* data() const {
        return data_;
    }

    const char* begin() const {
        return data_;
    }

    const char* end() const {
        return data_ + size_;
    }

    // 获取字符串的长度
    size_t size() const {
        return size_;
    }

    // 检查是否为空
    bool empty() const {
        return size_ == 0;
    }

    // 字符索引访问
    char operator[](size_t index) const {
        if (index >= size_) {
            throw std::out_of_range("Index out of range");
        }
        return data_[index];
    }

    // 转换为 std::string（如果需要所有权）
    std::string to_string() const {
        return std::string(data_, size_);
    }

    // 输出友元函数
    friend std::ostream& operator<<(std::ostream& os, const MyStringView& sv) {
        os.write(sv.data_, sv.size_);
        return os;
    }

    // 重载 operator==，与 char* 进行内容比较
    bool operator==(const char* other) const {
        return std::strncmp(data_, other, size_) == 0 && other[size_] == '\0';
    }

    // 重载 operator!=，与 char* 进行内容比较
    bool operator!=(const char* other) const {
        return !(*this == other);
    }
};