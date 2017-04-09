require 'spec_helper'

describe Pkcs11 do
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
        result = Pkcs11.C_GetSlotList(true, nil, count_pointer)
        expect(result).to eq Pkcs11::CKR_OK
      end

      it 'returns the slot list and count' do
        count_pointer = FFI::MemoryPointer.new(:ulong)
        result = Pkcs11.C_GetSlotList(true, nil, count_pointer)
        expect(result).to eq Pkcs11::CKR_OK
        expect(count_pointer.read_ulong).to eq 1

        slot_ids_pointer = FFI::MemoryPointer.new(:ulong, count_pointer.read_ulong)
        result = Pkcs11.C_GetSlotList(true, slot_ids_pointer, count_pointer)
        expect(result).to eq Pkcs11::CKR_OK
        expect(count_pointer.read_ulong).to eq 1
        expect(slot_ids_pointer[0].read_ulong).to eq 0
      end
    end

    describe '.C_OpenSession' do
      it 'returns CKR_OK' do
        session_handle = FFI::MemoryPointer.new(:ulong)
        result = Pkcs11.C_OpenSession(0, Pkcs11::CKF_SERIAL_SESSION, nil, nil, session_handle)
        expect(result).to eq Pkcs11::CKR_OK
      end
    end
  end
end
