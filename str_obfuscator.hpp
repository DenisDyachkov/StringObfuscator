#ifndef STR_OBFUSCATOR_HPP_
#define STR_OBFUSCATOR_HPP_

#ifdef _MSC_VER
	#define forceinline __forceinline
#else
#ifdef __GNUC__
	#define forceinline __attribute__((always_inline))
#endif
#endif

namespace detail {
	template<typename T, std::size_t index>
	struct encryptor {
		forceinline static constexpr void encrypt(T *dest, const T *str, T key) {
			dest[index] = str[index] ^ key;

			encryptor<T, index - 1>::encrypt(dest, str, key);
		}
	};

	template<typename T>
	struct encryptor<T, 0> {
		forceinline static constexpr void encrypt(T *dest, const T *str, T key) {
			dest[0] = str[0] ^ key;
		}
	};
};

class cryptor {
public:
	template<typename T, std::size_t S>
	class string_encryptor {
		static constexpr std::size_t max_value = 0xffffffff >> ((sizeof(std::size_t) - sizeof(T)) << 3);
	public:
		using value_type = T;

		constexpr string_encryptor(const value_type str[S], int key) :
			_buffer{}, _decrypted{ false }, _key{ static_cast<const value_type>(key % max_value) } {
			detail::encryptor<value_type, S - 1>::encrypt(_buffer, str, _key);
		}

		#ifdef __GNUC__
		__attribute__((noinline))
		#endif
			const value_type *decrypt() const {
			if (_decrypted) {
				return _buffer;
			}

			for (auto &c : _buffer) {
				c ^= _key;
			}

			_decrypted = true;

			return _buffer;
		}

	private:
		mutable value_type _buffer[S];
		mutable bool _decrypted;
		const value_type _key;
	};

	template<typename T, std::size_t S>
	static constexpr auto create(const T(&str)[S]) {
		return string_encryptor<T, S>{ str, S };
	}
};

#endif // STR_OBFUSCATOR_HPP_
