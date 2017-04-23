require 'spec_helper'

describe Pkcs11 do
  before(:all) do
    # brew install softhsm
    `rm -rf /usr/local/var/lib/softhsm/tokens/*`
    `softhsm2-util --init-token --slot 0 --id 0x00  --label 'zero' --pin 1234 --so-pin 5678`
  end

  let(:session_handle_pointer) { FFI::MemoryPointer.new(:ulong) }
  let(:session_handle) { session_handle_pointer.read_ulong }
  let(:session_flags) { Pkcs11::CKF_RW_SESSION | Pkcs11::CKF_SERIAL_SESSION }
  let(:invalid_pin) { '6666' }
  let(:pin) { '1234' }
  let(:so_pin) { '5678' }
  let(:data) { 'ABCDEFGH' }
  let(:md5_data) { '4783e784b4fa2fba9e4d6502dbc64f8f' }

  describe '.C_Initialize' do
    after { Pkcs11.C_Finalize(nil) }

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
                                      session_flags,
                                      nil, nil, session_handle_pointer)
        expect(result).to eq Pkcs11::CKR_OK

        result = Pkcs11.C_CloseSession(session_handle)
        expect(result).to eq Pkcs11::CKR_OK
      end

      it 'returns CKR_SLOT_ID_INVALID' do
        result = Pkcs11.C_OpenSession(6666,
                                      session_flags,
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

    context 'In a session' do
      before do
        result = Pkcs11.C_OpenSession(valid_slot,
                                      session_flags,
                                      nil, nil, session_handle_pointer)
        expect(result).to eq Pkcs11::CKR_OK
      end

      after do
        result = Pkcs11.C_CloseSession(session_handle)
        expect(result).to eq Pkcs11::CKR_OK
      end

      describe '.C_Login' do
        it 'returns CKR_OK' do
          result = Pkcs11.C_Login(session_handle, Pkcs11::CKU_USER, pin, pin.size)
          expect(result).to eq Pkcs11::CKR_OK

          result = Pkcs11::C_Logout(session_handle)
          expect(result).to eq Pkcs11::CKR_OK
        end

        it 'returns CKR_PIN_INCORRECT' do
          result = Pkcs11.C_Login(session_handle, Pkcs11::CKU_USER, invalid_pin, invalid_pin.size)
          expect(result).to eq Pkcs11::CKR_PIN_INCORRECT
        end
      end

      describe '.C_Logout' do
        it 'returns CKR_USER_NOT_LOGGED_IN' do
          result = Pkcs11::C_Logout(session_handle)
          expect(result).to eq Pkcs11::CKR_OK
        end
      end

      describe '.C_DigestInit' do
        it 'returns CKR_OK' do
          mechanism_pointer = FFI::MemoryPointer.new(:ulong)
          mechanism_pointer.write_ulong(Pkcs11::CKM_MD5)
          result = Pkcs11.C_DigestInit(session_handle, mechanism_pointer)
          expect(result).to eq Pkcs11::CKR_OK
        end
      end

      describe '.C_Digest' do
        it 'returns CKR_OPERATION_NOT_INITIALIZED' do
          digest = ' ' * 255
          digest_length_pointer = FFI::MemoryPointer.new(:ulong)
          digest_length_pointer.write_ulong(digest.size)
          result = Pkcs11.C_Digest(session_handle, data, data.size, digest, digest_length_pointer)
          expect(result).to eq Pkcs11::CKR_OPERATION_NOT_INITIALIZED
        end

        it 'returns CKR_OK' do
          mechanism_pointer = FFI::MemoryPointer.new(:ulong)
          mechanism_pointer.write_ulong(Pkcs11::CKM_MD5)
          result = Pkcs11.C_DigestInit(session_handle, mechanism_pointer)
          expect(result).to eq Pkcs11::CKR_OK

          digest = FFI::MemoryPointer.new(:uchar, 255)
          digest_length_pointer = FFI::MemoryPointer.new(:ulong)
          digest_length_pointer.write_ulong(255)
          result = Pkcs11.C_Digest(session_handle,
                                   FFI::MemoryPointer.from_string(data), data.bytesize,
                                   digest, digest_length_pointer)
          expect(result).to eq Pkcs11::CKR_OK

          digest_length = digest_length_pointer.read_ulong
          expect(digest_length).to eq 16

          bytes = digest.read_array_of_uchar(digest_length)
          hexadecimal = bytes.collect {|b| sprintf('%02x', b)}.join ''
          expect(hexadecimal).to eq md5_data
        end
      end
    end
  end
end
