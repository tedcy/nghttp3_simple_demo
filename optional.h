#pragma once
#include <utility>
#include <stdexcept>

template <typename T>
class MyOptional {
private:
    T* value_; // 指针用于动态管理对象
public:
    // 默认构造函数（无值情况）
    MyOptional() : value_(nullptr) {}

    // 构造一个值
    MyOptional(const T& value) : value_(new T(value)) {}

    // 移动构造
    MyOptional(T&& value) : value_(new T(std::move(value))) {}

    // 拷贝构造
    MyOptional(const MyOptional& other) {
        if (other.value_) {
            value_ = new T(*other.value_);
        } else {
            value_ = nullptr;
        }
    }

    // 移动构造
    MyOptional(MyOptional&& other) noexcept : value_(other.value_) {
        other.value_ = nullptr;
    }

    // 赋值运算符
    MyOptional& operator=(const MyOptional& other) {
        if (this != &other) {
            delete value_;
            value_ = other.value_ ? new T(*other.value_) : nullptr;
        }
        return *this;
    }

    // 移动赋值运算符
    MyOptional& operator=(MyOptional&& other) noexcept {
        if (this != &other) {
            delete value_;
            value_ = other.value_;
            other.value_ = nullptr;
        }
        return *this;
    }

    // 析构函数
    ~MyOptional() {
        delete value_;
    }

    // 检查是否有值
    bool has_value() const {
        return value_ != nullptr;
    }

    bool operator!() const {
        return !has_value();
    }

    // 获取值（引用类型）
    T& value() {
        if (!has_value()) {
            throw std::runtime_error("Accessing value of empty optional");
        }
        return *value_;
    }

    // 获取值（常量引用类型）
    const T& value() const {
        if (!has_value()) {
            throw std::runtime_error("Accessing value of empty optional");
        }
        return *value_;
    }

    // 重载解引用操作
    T& operator*() {
        return value();
    }

    const T& operator*() const {
        return value();
    }

    // 重载箭头操作符
    T* operator->() {
        return value_;
    }

    const T* operator->() const {
        return value_;
    }

    // 重置值
    void reset() {
        delete value_;
        value_ = nullptr;
    }
};