require 'ffi'
require 'pry'

module Pkcs11
  extend FFI::Library

  ffi_lib 'cryptoki'

  typedef :ulong, :CK_RV

  CKF_RW_SESSION = 0x00000002
  CKF_SERIAL_SESSION = 0x00000004

  CKU_SO = 0
  CKU_USER = 1
  CKU_CONTEXT_SPECIFIC = 2

  require 'pkcs11/return_value'

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

  import_function :C_OpenSession, [:ulong, :ulong, :pointer, :pointer, :pointer], :CK_RV
  import_function :C_CloseSession, [:ulong], :CK_RV

  import_function :C_Login, [:ulong, :ulong, :string, :ulong], :CK_RV
  import_function :C_Logout, [:ulong], :CK_RV

  import_function :C_Digest, [:pointer, :pointer, :ulong, :pointer, :pointer], :CK_RV
end
