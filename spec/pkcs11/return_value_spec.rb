require 'spec_helper'

describe Pkcs11::ReturnValue do
  describe '.[]' do
    it 'returns a ReturnValue instance' do
      expect(Pkcs11::ReturnValue[0]).to be_instance_of(Pkcs11::ReturnValue)
    end

    it 'raises if the error code is unknown' do
      expect { Pkcs11::ReturnValue[123456] }.to raise_error 'Unknown CKR result'
    end
  end

  describe '#ok?' do
    it 'returns true for value CKR_OK' do
      expect(Pkcs11::CKR_OK.ok?).to be true
    end

    it 'returns true for value 0' do
      value = Pkcs11::ReturnValue[0]
      expect(value.ok?).to be true
    end

    it 'returns false for anyhting else but CKR_OK' do
      expect(Pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED.ok?).to be false
    end

    it 'returns false for anything else but 0' do
      value = Pkcs11::ReturnValue[0x00000001]
      expect(value.ok?).to be false
    end
  end

  describe '#to_s' do
    it 'returns the CKR constant symbol' do
      expect(Pkcs11::CKR_OK.to_s).to eq 'CKR_OK'
      expect(Pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED.to_s).to eq 'CKR_CRYPTOKI_ALREADY_INITIALIZED'
    end
  end
end
