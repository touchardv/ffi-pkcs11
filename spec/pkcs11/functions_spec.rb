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
end
