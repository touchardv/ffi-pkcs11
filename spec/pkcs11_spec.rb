require "spec_helper"

describe Pkcs11 do
  it "has a version number" do
    expect(Pkcs11::VERSION).not_to be nil
  end
end
