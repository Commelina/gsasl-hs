{-# LANGUAGE CPP             #-}
{-# LANGUAGE LambdaCase      #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.SASL.Internal.Exception
  ( GSaslException(..)
  , GSaslErrCode(..)
  , throwGSaslErr
  , gsaslThen

  , pattern GSASL_OK
  , pattern NEEDS_MORE
  , pattern UNKNOWN_MECHANISM
  , pattern MECHANISM_CALLED_TOO_MANY_TIMES
  , pattern MALLOC_ERROR
  , pattern BASE64_ERROR
  , pattern CRYPTO_ERROR
  , pattern SASLPREP_ERROR
  , pattern MECHANISM_PARSE_ERROR
  , pattern AUTHENTICATION_ERROR
  , pattern INTEGRITY_ERROR
  , pattern NO_CLIENT_CODE
  , pattern NO_SERVER_CODE
  , pattern NO_CALLBACK
  , pattern NO_ANONYMOUS_TOKEN
  , pattern NO_AUTHID
  , pattern NO_AUTHZID
  , pattern NO_PASSWORD
  , pattern NO_PASSCODE
  , pattern NO_PIN
  , pattern NO_SERVICE
  , pattern NO_HOSTNAME
  , pattern NO_CB_TLS_UNIQUE
  , pattern NO_SAML20_IDP_IDENTIFIER
  , pattern NO_SAML20_REDIRECT_URL
  , pattern NO_OPENID20_REDIRECT_URL
  , pattern GSSAPI_RELEASE_BUFFER_ERROR
  , pattern GSSAPI_IMPORT_NAME_ERROR
  , pattern GSSAPI_INIT_SEC_CONTEXT_ERROR
  , pattern GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
  , pattern GSSAPI_UNWRAP_ERROR
  , pattern GSSAPI_WRAP_ERROR
  , pattern GSSAPI_ACQUIRE_CRED_ERROR
  , pattern GSSAPI_DISPLAY_NAME_ERROR
  , pattern GSSAPI_UNSUPPORTED_PROTECTION_ERROR
  , pattern SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
  , pattern SECURID_SERVER_NEED_NEW_PIN
  , pattern GSSAPI_ENCAPSULATE_TOKEN_ERROR
  , pattern GSSAPI_DECAPSULATE_TOKEN_ERROR
  , pattern GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
  , pattern GSSAPI_TEST_OID_SET_MEMBER_ERROR
  , pattern GSSAPI_RELEASE_OID_SET_ERROR
  ) where

import qualified Control.Exception as E
import           Foreign.C
import           GHC.Stack         (HasCallStack)
import           System.IO.Unsafe

#include <gsasl.h>

newtype GSaslException = GSaslException GSaslErrCode deriving (Show)
instance E.Exception GSaslException

newtype GSaslErrCode = GSaslErrCode CInt deriving (Eq, Num)
instance Show GSaslErrCode where
  -- FIXME: unsafePerformIO
  show (GSaslErrCode x) = unsafePerformIO $
    peekCString (gsasl_strerror_name x)

throwGSaslErr :: HasCallStack => CInt -> IO a
throwGSaslErr n = E.throwIO $ GSaslException (GSaslErrCode n)

gsaslThen :: HasCallStack => IO a -> CInt -> IO a
gsaslThen action errCode = do
  if errCode == 0 then action else throwGSaslErr errCode

foreign import ccall unsafe "gsasl.h gsasl_strerror_name"
  gsasl_strerror_name :: CInt -> CString

foreign import ccall unsafe "gsasl.h gsasl_strerror"
  gsasl_strerror :: CInt -> CString

pattern
    GSASL_OK
  , NEEDS_MORE
  , UNKNOWN_MECHANISM
  , MECHANISM_CALLED_TOO_MANY_TIMES
  , MALLOC_ERROR
  , BASE64_ERROR
  , CRYPTO_ERROR
  , SASLPREP_ERROR
  , MECHANISM_PARSE_ERROR
  , AUTHENTICATION_ERROR
  , INTEGRITY_ERROR
  , NO_CLIENT_CODE
  , NO_SERVER_CODE
  , NO_CALLBACK
  , NO_ANONYMOUS_TOKEN
  , NO_AUTHID
  , NO_AUTHZID
  , NO_PASSWORD
  , NO_PASSCODE
  , NO_PIN
  , NO_SERVICE
  , NO_HOSTNAME
  , NO_CB_TLS_UNIQUE
  , NO_SAML20_IDP_IDENTIFIER
  , NO_SAML20_REDIRECT_URL
  , NO_OPENID20_REDIRECT_URL
  , GSSAPI_RELEASE_BUFFER_ERROR
  , GSSAPI_IMPORT_NAME_ERROR
  , GSSAPI_INIT_SEC_CONTEXT_ERROR
  , GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
  , GSSAPI_UNWRAP_ERROR
  , GSSAPI_WRAP_ERROR
  , GSSAPI_ACQUIRE_CRED_ERROR
  , GSSAPI_DISPLAY_NAME_ERROR
  , GSSAPI_UNSUPPORTED_PROTECTION_ERROR
  , SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
  , SECURID_SERVER_NEED_NEW_PIN
  , GSSAPI_ENCAPSULATE_TOKEN_ERROR
  , GSSAPI_DECAPSULATE_TOKEN_ERROR
  , GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
  , GSSAPI_TEST_OID_SET_MEMBER_ERROR
  , GSSAPI_RELEASE_OID_SET_ERROR
  :: GSaslErrCode

pattern GSASL_OK                                = GSaslErrCode (#const GSASL_OK                                     )
pattern NEEDS_MORE                              = GSaslErrCode (#const GSASL_NEEDS_MORE                             )
pattern UNKNOWN_MECHANISM                       = GSaslErrCode (#const GSASL_UNKNOWN_MECHANISM                      )
pattern MECHANISM_CALLED_TOO_MANY_TIMES         = GSaslErrCode (#const GSASL_MECHANISM_CALLED_TOO_MANY_TIMES        )
pattern MALLOC_ERROR                            = GSaslErrCode (#const GSASL_MALLOC_ERROR                           )
pattern BASE64_ERROR                            = GSaslErrCode (#const GSASL_BASE64_ERROR                           )
pattern CRYPTO_ERROR                            = GSaslErrCode (#const GSASL_CRYPTO_ERROR                           )
pattern SASLPREP_ERROR                          = GSaslErrCode (#const GSASL_SASLPREP_ERROR                         )
pattern MECHANISM_PARSE_ERROR                   = GSaslErrCode (#const GSASL_MECHANISM_PARSE_ERROR                  )
pattern AUTHENTICATION_ERROR                    = GSaslErrCode (#const GSASL_AUTHENTICATION_ERROR                   )
pattern INTEGRITY_ERROR                         = GSaslErrCode (#const GSASL_INTEGRITY_ERROR                        )
pattern NO_CLIENT_CODE                          = GSaslErrCode (#const GSASL_NO_CLIENT_CODE                         )
pattern NO_SERVER_CODE                          = GSaslErrCode (#const GSASL_NO_SERVER_CODE                         )
pattern NO_CALLBACK                             = GSaslErrCode (#const GSASL_NO_CALLBACK                            )
pattern NO_ANONYMOUS_TOKEN                      = GSaslErrCode (#const GSASL_NO_ANONYMOUS_TOKEN                     )
pattern NO_AUTHID                               = GSaslErrCode (#const GSASL_NO_AUTHID                              )
pattern NO_AUTHZID                              = GSaslErrCode (#const GSASL_NO_AUTHZID                             )
pattern NO_PASSWORD                             = GSaslErrCode (#const GSASL_NO_PASSWORD                            )
pattern NO_PASSCODE                             = GSaslErrCode (#const GSASL_NO_PASSCODE                            )
pattern NO_PIN                                  = GSaslErrCode (#const GSASL_NO_PIN                                 )
pattern NO_SERVICE                              = GSaslErrCode (#const GSASL_NO_SERVICE                             )
pattern NO_HOSTNAME                             = GSaslErrCode (#const GSASL_NO_HOSTNAME                            )
pattern NO_CB_TLS_UNIQUE                        = GSaslErrCode (#const GSASL_NO_CB_TLS_UNIQUE                       )
pattern NO_SAML20_IDP_IDENTIFIER                = GSaslErrCode (#const GSASL_NO_SAML20_IDP_IDENTIFIER               )
pattern NO_SAML20_REDIRECT_URL                  = GSaslErrCode (#const GSASL_NO_SAML20_REDIRECT_URL                 )
pattern NO_OPENID20_REDIRECT_URL                = GSaslErrCode (#const GSASL_NO_OPENID20_REDIRECT_URL               )
pattern GSSAPI_RELEASE_BUFFER_ERROR             = GSaslErrCode (#const GSASL_GSSAPI_RELEASE_BUFFER_ERROR            )
pattern GSSAPI_IMPORT_NAME_ERROR                = GSaslErrCode (#const GSASL_GSSAPI_IMPORT_NAME_ERROR               )
pattern GSSAPI_INIT_SEC_CONTEXT_ERROR           = GSaslErrCode (#const GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR          )
pattern GSSAPI_ACCEPT_SEC_CONTEXT_ERROR         = GSaslErrCode (#const GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR        )
pattern GSSAPI_UNWRAP_ERROR                     = GSaslErrCode (#const GSASL_GSSAPI_UNWRAP_ERROR                    )
pattern GSSAPI_WRAP_ERROR                       = GSaslErrCode (#const GSASL_GSSAPI_WRAP_ERROR                      )
pattern GSSAPI_ACQUIRE_CRED_ERROR               = GSaslErrCode (#const GSASL_GSSAPI_ACQUIRE_CRED_ERROR              )
pattern GSSAPI_DISPLAY_NAME_ERROR               = GSaslErrCode (#const GSASL_GSSAPI_DISPLAY_NAME_ERROR              )
pattern GSSAPI_UNSUPPORTED_PROTECTION_ERROR     = GSaslErrCode (#const GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR    )
pattern SECURID_SERVER_NEED_ADDITIONAL_PASSCODE = GSaslErrCode (#const GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE)
pattern SECURID_SERVER_NEED_NEW_PIN             = GSaslErrCode (#const GSASL_SECURID_SERVER_NEED_NEW_PIN            )
pattern GSSAPI_ENCAPSULATE_TOKEN_ERROR          = GSaslErrCode (#const GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR         )
pattern GSSAPI_DECAPSULATE_TOKEN_ERROR          = GSaslErrCode (#const GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR         )
pattern GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR  = GSaslErrCode (#const GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR )
pattern GSSAPI_TEST_OID_SET_MEMBER_ERROR        = GSaslErrCode (#const GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR       )
pattern GSSAPI_RELEASE_OID_SET_ERROR            = GSaslErrCode (#const GSASL_GSSAPI_RELEASE_OID_SET_ERROR           )
