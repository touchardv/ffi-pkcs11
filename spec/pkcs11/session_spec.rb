require 'spec_helper'

describe Pkcs11::Session do
  include_context 'HSM'

  let(:session) { Pkcs11::Session.new }

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
      expect { session.close }.to raise_error Pkcs11::Error
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

  describe '#info' do
    before { session.open(valid_slot) }
    after { session.close }

    it 'returns a Hash with data' do
      data = session.info
      expect(data).to be_a Hash
      expect(data.keys).to match([:slot_id, :state, :flags, :u_device_error])
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
