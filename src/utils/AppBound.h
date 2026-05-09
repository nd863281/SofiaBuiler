 
#pragma once
#include <windows.h>
#include <objbase.h>
#include <vector>
#include <string>
namespace AppBound {
    enum ProtectionLevel : int {
        PROTECTION_NONE = 0,
        PROTECTION_PATH_VALIDATION = 1,
        PROTECTION_PATH_VALIDATION_WITH_INDIRECTION = 2,
        PROTECTION_MAX = 3
    };
    MIDL_INTERFACE("463ABECF-410D-407F-8AF5-0DF35A005CC8")
    IElevator : public IUnknown {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
            const WCHAR* crx_path, const WCHAR* browser_appid,
            const WCHAR* browser_version, const WCHAR* session_id,
            DWORD caller_proc_id, ULONG_PTR* proc_handle) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(
            ProtectionLevel protection_level, const BSTR plaintext,
            BSTR* ciphertext, DWORD* last_error) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(
            const BSTR ciphertext, BSTR* plaintext, DWORD* last_error) = 0;
    };
    MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
    IElevatorChrome : public IElevator {};
    MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
    IElevatorChromeBeta : public IElevator {};
    MIDL_INTERFACE("42D4A4CF-AE6A-4B4F-A8D5-BC4C45AC757A")
    IElevatorChromeDev : public IElevator {};
    MIDL_INTERFACE("89D73AE1-BFEF-4B5A-9F7E-DBC73E0059FA")
    IElevatorChromeCanary : public IElevator {};
    MIDL_INTERFACE("1F4DE4B7-C285-4A1F-9884-2C7F45F94E0E")
    IElevatorEdge : public IElevator {};
    std::vector<BYTE> DecryptAppBoundKey(const std::vector<BYTE>& ciphertext);
    std::vector<BYTE> DeriveV20MasterKey(const std::vector<BYTE>& encryptedKeyBlob);
    std::string DecryptAppBoundValue(const std::vector<BYTE>& encrypted, const std::vector<BYTE>& appBoundKey);
}
