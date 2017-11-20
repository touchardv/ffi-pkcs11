module Pkcs11
  extend FFI::Library

  ffi_lib 'cryptoki'

  typedef :ulong, :CK_RV
end
