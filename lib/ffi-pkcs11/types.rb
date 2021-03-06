module Pkcs11
  CKS_RO_PUBLIC_SESSION = 0
  CKS_RO_USER_FUNCTIONS = 1
  CKS_RW_PUBLIC_SESSION = 2
  CKS_RW_USER_FUNCTIONS = 3
  CKS_RW_SO_FUNCTIONS =  4

  CKF_RW_SESSION = 0x00000002
  CKF_SERIAL_SESSION = 0x00000004

  CKM_MD5 = 0x00000210
  CKM_SHA_1 = 0x00000220
  CKM_VENDOR_DEFINED = 0x80000000

  CKU_SO = 0
  CKU_USER = 1
  CKU_CONTEXT_SPECIFIC = 2

  class CK_INFO < FFI::Struct
    layout :cryptoki_version, [:uchar, 2],
      :manufacturer_id, [:uchar, 32],
      :flags, :ulong,
      :library_description, [:uchar, 32],
      :library_version, [:uchar, 2]
  end

  class CK_SESSION_INFO < FFI::Struct
    layout :slot_id, :ulong,
      :state, :ulong,
      :flags, :ulong,
      :u_device_error, :ulong
  end

  enum :CK_ATTRIBUTE_TYPE, [
    :CKA_CLASS,  0x00000000,
    :CKA_TOKEN,  0x00000001,
    :CKA_PRIVATE,  0x00000002,
    :CKA_LABEL,  0x00000003
  ]

  class CK_ATTRIBUTE < FFI::Struct
    layout :type, :CK_ATTRIBUTE_TYPE,
      :value, :pointer,
      :value_len, :ulong
  end

  class CK_TOKEN_INFO < FFI::Struct
    layout :label, [:uchar, 32],
      :manufacturer_id, [:uchar, 32],
      :model, [:uchar, 16],
      :serial_number, [:char, 16],
      :flags, :ulong,
      :u_max_session_count, :ulong,
      :u_session_count, :ulong,
      :u_max_rw_session_count, :ulong,
      :u_rw_session_count, :ulong,
      :u_max_pin_len, :ulong,
      :u_min_pin_len, :ulong,
      :u_total_public_memory, :ulong,
      :u_free_public_memory, :ulong,
      :u_total_private_memory, :ulong,
      :u_free_private_memory, :ulong,
      :hardware_version, [:char, 2],
      :firmware_version, [:char, 2],
      :utc_time, [:char, 16]
  end
end
