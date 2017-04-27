require 'spec_helper'

describe Pkcs11::Session do
  before(:all) do
    # brew install softhsm
    `rm -rf /usr/local/var/lib/softhsm/tokens/*`
    `softhsm2-util --init-token --slot 0 --id 0x00  --label 'zero' --pin 1234 --so-pin 5678`
  end

  let(:session) { Pkcs11::Session.new }
  let(:pin) { '1234' }

  let(:valid_slot) do
    count_pointer = FFI::MemoryPointer.new(:ulong)
    result = Pkcs11.C_GetSlotList(false, nil, count_pointer)
    expect(result).to eq Pkcs11::CKR_OK
    slot_ids_pointer = FFI::MemoryPointer.new(:ulong, count_pointer.read_ulong)
    result = Pkcs11.C_GetSlotList(false, slot_ids_pointer, count_pointer)
    expect(result).to eq Pkcs11::CKR_OK
    slot_ids_pointer[0].read_ulong
  end

  before(:all) do
    result = Pkcs11.C_Initialize(nil)
    expect(result).to eq Pkcs11::CKR_OK
  end

  after(:all) do
    result = Pkcs11.C_Finalize(nil)
    expect(result).to eq Pkcs11::CKR_OK
  end

  describe '#close' do
    it 'raises an error if not open' do
      expect { session.close }.to raise_error RuntimeError
    end

    it 'closes an open session' do
      session.open(valid_slot)
      session.close
      expect(session.closed?).to eq true
    end
  end

  describe '#closed?' do
    it 'return true' do
      session.open(valid_slot)
      expect(session.closed?).to eq false
    end

    it 'returns false' do
      expect(session.closed?).to eq true
    end
  end

  describe '#login' do
    before { session.open(valid_slot) }
    after { session.close }

    context 'with an argument block' do
      it 'calls the block' do
        called = false
        session.login(pin) do |arg|
          called = true
        end
        expect(called).to eq true
      end

      it 'logouts automatically' do
        expect(Pkcs11).to receive(:C_Logout).and_call_original
        session.login(pin) {|_| nil}
      end
    end
  end

  describe '#open' do
    context 'with an argument block' do
      it 'calls the block' do
        called = false
        session.open(valid_slot) do |arg|
          expect(arg.closed?).to eq false
          called = true
        end
        expect(called).to eq true
      end

      it 'closes automatically' do
        expect(Pkcs11).to receive(:C_CloseSession).and_call_original
        session.open(valid_slot) {|_| nil}
        expect(session.closed?).to eq true
      end
    end

    it 'stays opened when no block is provided' do
      session.open(valid_slot)
      expect(session.closed?).to eq false
    end
  end
end
