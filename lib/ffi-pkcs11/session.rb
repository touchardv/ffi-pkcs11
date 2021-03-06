module Pkcs11
  class Session
    def initialize
      @session_pointer = FFI::MemoryPointer.new(:ulong)
      @session_pointer.write_ulong(0)
    end

    def close
      result = Pkcs11.C_CloseSession(session_handle)
      check result

      @session_pointer.write_ulong(0)
    end

    def closed?
      @session_pointer.read_ulong == 0
    end

    def info
      session_info = Pkcs11::CK_SESSION_INFO.new
      result = Pkcs11::C_GetSessionInfo(session_handle, session_info)
      check result
      {
        slot_id: session_info[:slot_id],
        state: session_info[:state],
        flags: session_info[:flags],
        u_device_error: session_info[:u_device_error]
      }
    end

    def login(pin)
      result = Pkcs11.C_Login(session_handle, Pkcs11::CKU_USER, pin, pin.size)
      check result
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
      check result
    end

    def open(slot, flags = default_flags)
      result = Pkcs11.C_OpenSession(slot,
                                    flags,
                                    nil, nil, @session_pointer)
      check result
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

    def check(result)
      raise Pkcs11::Error.new(result.to_s) unless result == Pkcs11::CKR_OK
    end

    def default_flags
      Pkcs11::CKF_RW_SESSION | Pkcs11::CKF_SERIAL_SESSION
    end
  end
end
