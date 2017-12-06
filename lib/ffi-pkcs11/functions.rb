module Pkcs11
  def self.import_function(function_name, *args)
    function_symbol = "native_#{function_name}".to_sym
    attach_function(function_symbol, function_name, *args)

    self.class.send(:define_method, function_name) do |*arguments|
      if ENV['PKCS11_DEBUG']
        start_time = Time.now
        begin
          result = send(function_symbol, *arguments)
        ensure
          end_time = Time.now
          puts "#{function_name} - #{result} - #{end_time - start_time}"
        end
        ReturnValue[result]
      else
        result = send(function_symbol, *arguments)
        ReturnValue[result]
      end
    end
  end

  import_function :C_Initialize, [:pointer], :CK_RV
  import_function :C_Finalize, [:pointer], :CK_RV

  import_function :C_GetInfo, [:pointer], :CK_RV
  import_function :C_GetSlotList, [:bool, :pointer, :pointer], :CK_RV
  import_function :C_GetTokenInfo, [:ulong, :pointer], :CK_RV

  import_function :C_GetSessionInfo, [:ulong, :pointer], :CK_RV
  import_function :C_OpenSession, [:ulong, :ulong, :pointer, :pointer, :pointer], :CK_RV
  import_function :C_CloseSession, [:ulong], :CK_RV

  import_function :C_Login, [:ulong, :ulong, :string, :ulong], :CK_RV
  import_function :C_Logout, [:ulong], :CK_RV

  import_function :C_FindObjectsInit, [:ulong, :pointer, :ulong], :CK_RV
  import_function :C_FindObjects, [:ulong, :pointer, :ulong, :pointer], :CK_RV
  import_function :C_FindObjectsFinal, [:ulong], :CK_RV

  import_function :C_DigestInit, [:ulong, :pointer], :CK_RV
  import_function :C_Digest, [:ulong, :pointer, :ulong, :pointer, :pointer], :CK_RV
end
