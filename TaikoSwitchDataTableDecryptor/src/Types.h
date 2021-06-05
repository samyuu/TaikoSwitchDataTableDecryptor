#pragma once
#include <stdint.h>
#include <string>
#include <string_view>
#include <array>
#include <vector>
#include <memory>
#include <functional>
#include <tuple>
#include <assert.h>

using i8 = int8_t;
using u8 = uint8_t;
using i16 = int16_t;
using u16 = uint16_t;
using i32 = int32_t;
using u32 = uint32_t;
using i64 = int64_t;
using u64 = uint64_t;
using f32 = float;
using f64 = double;

struct NonCopyable
{
	NonCopyable() = default;
	~NonCopyable() = default;

	NonCopyable(const NonCopyable&) = delete;
	NonCopyable& operator=(const NonCopyable&) = delete;
};
