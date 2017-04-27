require 'ffi'

module Pkcs11
  extend FFI::Library

  ffi_lib 'cryptoki'

  typedef :ulong, :CK_RV

  CKS_RO_PUBLIC_SESSION = 0
  CKS_RO_USER_FUNCTIONS = 1
  CKS_RW_PUBLIC_SESSION = 2
  CKS_RW_USER_FUNCTIONS = 3
  CKS_RW_SO_FUNCTIONS =  4

  class CK_SESSION_INFO < FFI::Struct
    layout :slot_id, :ulong,
      :state, :ulong,
      :flags, :ulong,
      :u_device_error, :ulong
  end

  CKF_RW_SESSION = 0x00000002
  CKF_SERIAL_SESSION = 0x00000004

  CKM_MD5 = 0x00000210
  CKM_SHA_1 = 0x00000220
  CKM_VENDOR_DEFINED = 0x80000000

  CKU_SO = 0
  CKU_USER = 1
  CKU_CONTEXT_SPECIFIC = 2

  def self.import_function(function_name, *args)
    function_symbol = "native_#{function_name}".to_sym
    attach_function(function_symbol, function_name, *args)

    self.class.send(:define_method, function_name) do |*arguments|
      result = send(function_symbol, *arguments)
      ReturnValue[result]
    end
  end

  import_function :C_Initialize, [:pointer], :CK_RV
  import_function :C_Finalize, [:pointer], :CK_RV

  import_function :C_GetSlotList, [:bool, :pointer, :pointer], :CK_RV

  import_function :C_GetSessionInfo, [:ulong, :pointer], :CK_RV
  import_function :C_OpenSession, [:ulong, :ulong, :pointer, :pointer, :pointer], :CK_RV
  import_function :C_CloseSession, [:ulong], :CK_RV

  import_function :C_Login, [:ulong, :ulong, :string, :ulong], :CK_RV
  import_function :C_Logout, [:ulong], :CK_RV

  import_function :C_DigestInit, [:ulong, :pointer], :CK_RV
  import_function :C_Digest, [:ulong, :pointer, :ulong, :pointer, :pointer], :CK_RV
end
