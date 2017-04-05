require 'ffi'

module Pkcs11
  extend FFI::Library

  ffi_lib 'cryptoki'

  typedef :ulong, :CK_RV

  CKR_OK = 0x00000000
  CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190
  CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191

  attach_function :C_Initialize, [:pointer], :CK_RV
  attach_function :C_Finalize, [:pointer], :CK_RV

  attach_function :C_OpenSession, [:ulong, :ulong, :pointer, :pointer, :pointer], :CK_RV
  attach_function :C_CloseSession, [:pointer], :CK_RV

  attach_function :C_Login, [:pointer, :ulong, :pointer, :ulong], :CK_RV
  attach_function :C_Logout, [:pointer], :CK_RV

  attach_function :C_Digest, [:pointer, :pointer, :ulong, :pointer, :pointer], :CK_RV
end
