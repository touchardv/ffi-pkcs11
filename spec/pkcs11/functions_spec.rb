require 'spec_helper'

describe Pkcs11 do
  before(:all) do
    # brew install softhsm
    `rm -rf /usr/local/var/lib/softhsm/tokens/*`
    `softhsm2-util --init-token --slot 0 --id 0x00  --label 'zero' --pin 1234 --so-pin 5678`
  end

  let(:session_handle_pointer) { FFI::MemoryPointer.new(:ulong) }
  let(:session_handle) { session_handle_pointer.read_ulong }
  let(:pin) { '1234' }
  let(:so_pin) { '5678' }
  
  after { Pkcs11.C_Finalize(nil) }

  describe '.C_Initialize' do
    it 'returns CKR_OK' do
      result = Pkcs11.C_Initialize(nil)
      expect(result).to eq Pkcs11::CKR_OK
    end

    it 'returns CKR_CRYPTOKI_ALREADY_INITIALIZED' do
      result = Pkcs11.C_Initialize(nil)
      expect(result).to eq Pkcs11::CKR_OK

      result = Pkcs11.C_Initialize(nil)
      expect(result).to eq Pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED
    end
  end

  describe '.C_Finalize' do
    it 'returns CKR_OK' do
      result = Pkcs11.C_Initialize(nil)
      expect(result).to eq Pkcs11::CKR_OK

      result = Pkcs11.C_Finalize(nil)
      expect(result).to eq Pkcs11::CKR_OK
    end

    it 'returns CKR_CRYPTOKI_NOT_INITIALIZED' do
      result = Pkcs11.C_Finalize(nil)
      expect(result).to eq Pkcs11::CKR_CRYPTOKI_NOT_INITIALIZED
    end
  end

  context 'Initialized' do
    before do
      result = Pkcs11.C_Initialize(nil)
      expect(result).to eq Pkcs11::CKR_OK
    end

    after do
      result = Pkcs11.C_Finalize(nil)
      expect(result).to eq Pkcs11::CKR_OK
    end

    describe '.C_GetSlotList' do
      it 'returns CKR_OK' do
        count_pointer = FFI::MemoryPointer.new(:ulong)
        result = Pkcs11.C_GetSlotList(false, nil, count_pointer)
        expect(result).to eq Pkcs11::CKR_OK
      end

      it 'returns the slot list and count' do
        count_pointer = FFI::MemoryPointer.new(:ulong)
        result = Pkcs11.C_GetSlotList(false, nil, count_pointer)
        expect(result).to eq Pkcs11::CKR_OK
        expect(count_pointer.read_ulong).to eq 2

        slot_ids_pointer = FFI::MemoryPointer.new(:ulong, count_pointer.read_ulong)
        result = Pkcs11.C_GetSlotList(false, slot_ids_pointer, count_pointer)
        expect(result).to eq Pkcs11::CKR_OK
        expect(count_pointer.read_ulong).to eq 2
      end
    end

    let(:valid_slot) do
      count_pointer = FFI::MemoryPointer.new(:ulong)
      result = Pkcs11.C_GetSlotList(false, nil, count_pointer)
      expect(result).to eq Pkcs11::CKR_OK
      slot_ids_pointer = FFI::MemoryPointer.new(:ulong, count_pointer.read_ulong)
      result = Pkcs11.C_GetSlotList(false, slot_ids_pointer, count_pointer)
      expect(result).to eq Pkcs11::CKR_OK
      slot_ids_pointer[0].read_ulong
    end

    describe '.C_OpenSession' do
      it 'returns CKR_OK' do
        result = Pkcs11.C_OpenSession(valid_slot,
                                      Pkcs11::CKF_SERIAL_SESSION | Pkcs11::CKF_SERIAL_SESSION,
                                      nil, nil, session_handle_pointer)
        expect(result).to eq Pkcs11::CKR_OK

        result = Pkcs11.C_CloseSession(session_handle)
        expect(result).to eq Pkcs11::CKR_OK
      end

      it 'returns CKR_SLOT_ID_INVALID' do
        result = Pkcs11.C_OpenSession(6666,
                                      Pkcs11::CKF_SERIAL_SESSION | Pkcs11::CKF_SERIAL_SESSION,
                                      nil, nil, session_handle_pointer)
        expect(result).to eq Pkcs11::CKR_SLOT_ID_INVALID
      end
    end

    describe '.C_CloseSession' do
      it 'returns CKR_SESSION_HANDLE_INVALID' do
        result = Pkcs11.C_CloseSession(0)
        expect(result).to eq Pkcs11::CKR_SESSION_HANDLE_INVALID
      end
    end

    describe '.C_Login' do
      it 'returns CKR_OK' do
        result = Pkcs11.C_OpenSession(valid_slot,
                                      Pkcs11::CKF_SERIAL_SESSION | Pkcs11::CKF_SERIAL_SESSION,
                                      nil, nil, session_handle_pointer)
        expect(result).to eq Pkcs11::CKR_OK

        result = Pkcs11.C_Login(session_handle, Pkcs11::CKU_USER, pin, pin.size)        
        expect(result).to eq Pkcs11::CKR_OK

        result = Pkcs11::C_Logout(session_handle)
        expect(result).to eq Pkcs11::CKR_OK
      end

      it 'returns CKR_PIN_INCORRECT' do
        # TODO
      end
    end
  end
end

