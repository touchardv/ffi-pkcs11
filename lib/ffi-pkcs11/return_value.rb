module Pkcs11
  RETURN_VALUES = {}

  class ReturnValue
    attr_reader :result

    def self.[](result)
      if RETURN_VALUES.has_key? result
        RETURN_VALUES[result]
      elsif result >= CKR_VENDOR_DEFINED.result
        ReturnValue.new(result, :CKR_VENDOR_DEFINED)
      else
        raise "Unknown CKR result: #{result}"
      end
    end

    def ok?
      @result == 0
    end

    def inspect
      to_s
    end

    def to_s
      if @symbol == :CKR_VENDOR_DEFINED
        "#{@symbol}_#{sprintf('0x%x', @result)}"
      else
        @symbol.to_s
      end
    end

    private

    def initialize(result, symbol)
      @result = result
      @symbol = symbol
    end
  end

  def self.define_code(symbol, result)
    return_value = ReturnValue.new(result, symbol)
    self.const_set symbol, return_value

    RETURN_VALUES[result] = return_value
  end

  define_code :CKR_OK,                                0x00000000
  define_code :CKR_CANCEL,                            0x00000001
  define_code :CKR_HOST_MEMORY,                       0x00000002
  define_code :CKR_SLOT_ID_INVALID,                   0x00000003

  define_code :CKR_GENERAL_ERROR,                     0x00000005
  define_code :CKR_FUNCTION_FAILED,                   0x00000006

  define_code :CKR_ARGUMENTS_BAD,                     0x00000007
  define_code :CKR_NO_EVENT,                          0x00000008
  define_code :CKR_NEED_TO_CREATE_THREADS,            0x00000009
  define_code :CKR_CANT_LOCK,                         0x0000000A

  define_code :CKR_ATTRIBUTE_READ_ONLY,               0x00000010
  define_code :CKR_ATTRIBUTE_SENSITIVE,               0x00000011
  define_code :CKR_ATTRIBUTE_TYPE_INVALID,            0x00000012
  define_code :CKR_ATTRIBUTE_result_INVALID,           0x00000013
  define_code :CKR_DATA_INVALID,                      0x00000020
  define_code :CKR_DATA_LEN_RANGE,                    0x00000021
  define_code :CKR_DEVICE_ERROR,                      0x00000030
  define_code :CKR_DEVICE_MEMORY,                     0x00000031
  define_code :CKR_DEVICE_REMOVED,                    0x00000032
  define_code :CKR_ENCRYPTED_DATA_INVALID,            0x00000040
  define_code :CKR_ENCRYPTED_DATA_LEN_RANGE,          0x00000041
  define_code :CKR_FUNCTION_CANCELED,                 0x00000050
  define_code :CKR_FUNCTION_NOT_PARALLEL,             0x00000051

  define_code :CKR_FUNCTION_NOT_SUPPORTED,            0x00000054

  define_code :CKR_KEY_HANDLE_INVALID,                0x00000060

  define_code :CKR_KEY_SIZE_RANGE,                    0x00000062
  define_code :CKR_KEY_TYPE_INCONSISTENT,             0x00000063

  define_code :CKR_KEY_NOT_NEEDED,                    0x00000064
  define_code :CKR_KEY_CHANGED,                       0x00000065
  define_code :CKR_KEY_NEEDED,                        0x00000066
  define_code :CKR_KEY_INDIGESTIBLE,                  0x00000067
  define_code :CKR_KEY_FUNCTION_NOT_PERMITTED,        0x00000068
  define_code :CKR_KEY_NOT_WRAPPABLE,                 0x00000069
  define_code :CKR_KEY_UNEXTRACTABLE,                 0x0000006A

  define_code :CKR_MECHANISM_INVALID,                 0x00000070
  define_code :CKR_MECHANISM_PARAM_INVALID,           0x00000071

  define_code :CKR_OBJECT_HANDLE_INVALID,             0x00000082
  define_code :CKR_OPERATION_ACTIVE,                  0x00000090
  define_code :CKR_OPERATION_NOT_INITIALIZED,         0x00000091
  define_code :CKR_PIN_INCORRECT,                     0x000000A0
  define_code :CKR_PIN_INVALID,                       0x000000A1
  define_code :CKR_PIN_LEN_RANGE,                     0x000000A2

  define_code :CKR_PIN_EXPIRED,                       0x000000A3
  define_code :CKR_PIN_LOCKED,                        0x000000A4

  define_code :CKR_SESSION_CLOSED,                    0x000000B0
  define_code :CKR_SESSION_COUNT,                     0x000000B1
  define_code :CKR_SESSION_HANDLE_INVALID,            0x000000B3
  define_code :CKR_SESSION_PARALLEL_NOT_SUPPORTED,    0x000000B4
  define_code :CKR_SESSION_READ_ONLY,                 0x000000B5
  define_code :CKR_SESSION_EXISTS,                    0x000000B6

  define_code :CKR_SESSION_READ_ONLY_EXISTS,          0x000000B7
  define_code :CKR_SESSION_READ_WRITE_SO_EXISTS,      0x000000B8

  define_code :CKR_SIGNATURE_INVALID,                 0x000000C0
  define_code :CKR_SIGNATURE_LEN_RANGE,               0x000000C1
  define_code :CKR_TEMPLATE_INCOMPLETE,               0x000000D0
  define_code :CKR_TEMPLATE_INCONSISTENT,             0x000000D1
  define_code :CKR_TOKEN_NOT_PRESENT,                 0x000000E0
  define_code :CKR_TOKEN_NOT_RECOGNIZED,              0x000000E1
  define_code :CKR_TOKEN_WRITE_PROTECTED,             0x000000E2
  define_code :CKR_UNWRAPPING_KEY_HANDLE_INVALID,     0x000000F0
  define_code :CKR_UNWRAPPING_KEY_SIZE_RANGE,         0x000000F1
  define_code :CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,  0x000000F2
  define_code :CKR_USER_ALREADY_LOGGED_IN,            0x00000100
  define_code :CKR_USER_NOT_LOGGED_IN,                0x00000101
  define_code :CKR_USER_PIN_NOT_INITIALIZED,          0x00000102
  define_code :CKR_USER_TYPE_INVALID,                 0x00000103

  define_code :CKR_USER_ANOTHER_ALREADY_LOGGED_IN,    0x00000104
  define_code :CKR_USER_TOO_MANY_TYPES,               0x00000105

  define_code :CKR_WRAPPED_KEY_INVALID,               0x00000110
  define_code :CKR_WRAPPED_KEY_LEN_RANGE,             0x00000112
  define_code :CKR_WRAPPING_KEY_HANDLE_INVALID,       0x00000113
  define_code :CKR_WRAPPING_KEY_SIZE_RANGE,           0x00000114
  define_code :CKR_WRAPPING_KEY_TYPE_INCONSISTENT,    0x00000115
  define_code :CKR_RANDOM_SEED_NOT_SUPPORTED,         0x00000120

  define_code :CKR_RANDOM_NO_RNG,                     0x00000121

  define_code :CKR_DOMAIN_PARAMS_INVALID,             0x00000130

  define_code :CKR_BUFFER_TOO_SMALL,                  0x00000150
  define_code :CKR_SAVED_STATE_INVALID,               0x00000160
  define_code :CKR_INFORMATION_SENSITIVE,             0x00000170
  define_code :CKR_STATE_UNSAVEABLE,                  0x00000180

  define_code :CKR_CRYPTOKI_NOT_INITIALIZED,          0x00000190
  define_code :CKR_CRYPTOKI_ALREADY_INITIALIZED,      0x00000191
  define_code :CKR_MUTEX_BAD,                         0x000001A0
  define_code :CKR_MUTEX_NOT_LOCKED,                  0x000001A1

  define_code :CKR_NEW_PIN_MODE,                      0x000001B0
  define_code :CKR_NEXT_OTP,                          0x000001B1

  define_code :CKR_FUNCTION_REJECTED,                 0x00000200

  define_code :CKR_VENDOR_DEFINED,                    0x80000000
end
