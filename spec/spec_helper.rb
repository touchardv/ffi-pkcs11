$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "ffi-pkcs11"
require 'pry'

RSpec.shared_context 'HSM' do
  before(:all) do
    if FFI::Platform::OS == 'darwin'
      # brew install softhsm
      `rm -rf /usr/local/var/lib/softhsm/tokens/*`
      `softhsm2-util --init-token --slot 0 --id 0x00  --label 'zero' --pin 1234 --so-pin 5678`
    end
  end

  let(:pin) { ENV['PIN'] || '1234' }

  let(:valid_slot) do
    return ENV['WLD_SLOT_ID'].to_i if ENV.has_key? 'WLD_SLOT_ID'

    count_pointer = FFI::MemoryPointer.new(:ulong)
    result = Pkcs11.C_GetSlotList(false, nil, count_pointer)
    expect(result).to eq Pkcs11::CKR_OK
    slot_ids_pointer = FFI::MemoryPointer.new(:ulong, count_pointer.read_ulong)
    result = Pkcs11.C_GetSlotList(false, slot_ids_pointer, count_pointer)
    expect(result).to eq Pkcs11::CKR_OK
    slot_ids_pointer[0].read_ulong
  end
end
