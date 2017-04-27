module Pkcs11
  class Session
    def initialize
      @session_pointer = FFI::MemoryPointer.new(:ulong)
      @session_pointer.write_ulong(0)
    end

    def close
      result = Pkcs11.C_CloseSession(session_handle)
      raise unless result == Pkcs11::CKR_OK

      @session_pointer.write_ulong(0)
    end

    def closed?
      @session_pointer.read_ulong == 0
    end

    def login(pin)
      result = Pkcs11.C_Login(session_handle, Pkcs11::CKU_USER, pin, pin.size)
      raise unless result == Pkcs11::CKR_OK
      if block_given?
        begin
          yield self
        ensure
          logout
        end
      end
    end

    def logout
      result = Pkcs11::C_Logout(session_handle)
      raise unless result == Pkcs11::CKR_OK
    end

    def open(slot, flags = default_flags)
      result = Pkcs11.C_OpenSession(slot,
                                    flags,
                                    nil, nil, @session_pointer)
      raise unless result == Pkcs11::CKR_OK
      if block_given?
        begin
          yield self
        ensure
          close
        end
      end
    end

    def session_handle
      @session_pointer.read_ulong
    end

    private

    def default_flags
      Pkcs11::CKF_RW_SESSION | Pkcs11::CKF_SERIAL_SESSION
    end
  end
end
