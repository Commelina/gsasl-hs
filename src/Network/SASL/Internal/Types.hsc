{-# LANGUAGE CPP             #-}
{-# LANGUAGE LambdaCase      #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.SASL.Internal.Types
  ( GSaslContext (..)
  , GSaslSession (..)
  , Property (..)
  , CallbackFn
  , Progress (..)

  , pattern PropertyAuthid
  , pattern PropertyAuthzid
  , pattern PropertyPassword
  , pattern PropertyAnonymousToken
  , pattern PropertyService
  , pattern PropertyHostname
  , pattern PropertyGssapiDisplayName
  , pattern PropertyPasscode
  , pattern PropertySuggestedPin
  , pattern PropertyPin
  , pattern PropertyRealm
  , pattern PropertyDigestMd5HashedPassword
  , pattern PropertyQops
  , pattern PropertyQop
  , pattern PropertyScramIter
  , pattern PropertyScramSalt
  , pattern PropertyScramSaltedPassword
  , pattern PropertyScramServerkey
  , pattern PropertyScramStoredkey
  , pattern PropertyCBTlsUnique
  , pattern PropertySaml20IdpIdentifier
  , pattern PropertySaml20RedirectUrl
  , pattern PropertyOpenid20RedirectUrl
  , pattern PropertyOpenid20OutcomeData
  , pattern PropertySaml20AuthenticateINBrowser
  , pattern PropertyOpenid20AuthenticateINBrowser
  , pattern PropertyValidateSimple
  , pattern PropertyValidateExternal
  , pattern PropertyValidateAnonymous
  , pattern PropertyValidateGssapi
  , pattern PropertyValidateSecurid
  , pattern PropertyValidateSaml20
  , pattern PropertyValidateOpenid20
  ) where

#include <gsasl.h>

import           Data.Void (Void)
import           Foreign
import           Foreign.C

-- libgsasl Context. Actually a pointer
newtype GSaslContext =
  GSaslContext { unGSaslContext :: Ptr Void } deriving (Storable)

-- libgsasl Session. Actually a pointer
newtype GSaslSession =
  GSaslSession { unGSaslSession :: Ptr Void } deriving (Storable)

-- libgsasl Properties
newtype Property = Property CInt deriving (Eq, Num)
pattern
    PropertyAuthid
  , PropertyAuthzid
  , PropertyPassword
  , PropertyAnonymousToken
  , PropertyService
  , PropertyHostname
  , PropertyGssapiDisplayName
  , PropertyPasscode
  , PropertySuggestedPin
  , PropertyPin
  , PropertyRealm
  , PropertyDigestMd5HashedPassword
  , PropertyQops
  , PropertyQop
  , PropertyScramIter
  , PropertyScramSalt
  , PropertyScramSaltedPassword
  , PropertyScramServerkey
  , PropertyScramStoredkey
  , PropertyCBTlsUnique
  , PropertySaml20IdpIdentifier
  , PropertySaml20RedirectUrl
  , PropertyOpenid20RedirectUrl
  , PropertyOpenid20OutcomeData
  , PropertySaml20AuthenticateINBrowser
  , PropertyOpenid20AuthenticateINBrowser
  , PropertyValidateSimple
  , PropertyValidateExternal
  , PropertyValidateAnonymous
  , PropertyValidateGssapi
  , PropertyValidateSecurid
  , PropertyValidateSaml20
  , PropertyValidateOpenid20
  :: Property

pattern PropertyAuthid                        = Property (#const GSASL_AUTHID)
pattern PropertyAuthzid                       = Property (#const GSASL_AUTHZID)
pattern PropertyPassword                      = Property (#const GSASL_PASSWORD)
pattern PropertyAnonymousToken                = Property (#const GSASL_ANONYMOUS_TOKEN)
pattern PropertyService                       = Property (#const GSASL_SERVICE)
pattern PropertyHostname                      = Property (#const GSASL_HOSTNAME)
pattern PropertyGssapiDisplayName             = Property (#const GSASL_GSSAPI_DISPLAY_NAME)
pattern PropertyPasscode                      = Property (#const GSASL_PASSCODE)
pattern PropertySuggestedPin                  = Property (#const GSASL_SUGGESTED_PIN)
pattern PropertyPin                           = Property (#const GSASL_PIN)
pattern PropertyRealm                         = Property (#const GSASL_REALM)
pattern PropertyDigestMd5HashedPassword       = Property (#const GSASL_DIGEST_MD5_HASHED_PASSWORD)
pattern PropertyQops                          = Property (#const GSASL_QOPS)
pattern PropertyQop                           = Property (#const GSASL_QOP)
pattern PropertyScramIter                     = Property (#const GSASL_SCRAM_ITER)
pattern PropertyScramSalt                     = Property (#const GSASL_SCRAM_SALT)
pattern PropertyScramSaltedPassword           = Property (#const GSASL_SCRAM_SALTED_PASSWORD)
pattern PropertyScramServerkey                = Property (#const GSASL_SCRAM_SERVERKEY)
pattern PropertyScramStoredkey                = Property (#const GSASL_SCRAM_STOREDKEY)
pattern PropertyCBTlsUnique                   = Property (#const GSASL_CB_TLS_UNIQUE)
pattern PropertySaml20IdpIdentifier           = Property (#const GSASL_SAML20_IDP_IDENTIFIER)
pattern PropertySaml20RedirectUrl             = Property (#const GSASL_SAML20_REDIRECT_URL)
pattern PropertyOpenid20RedirectUrl           = Property (#const GSASL_OPENID20_REDIRECT_URL)
pattern PropertyOpenid20OutcomeData           = Property (#const GSASL_OPENID20_OUTCOME_DATA)
pattern PropertySaml20AuthenticateINBrowser   = Property (#const GSASL_SAML20_AUTHENTICATE_IN_BROWSER)
pattern PropertyOpenid20AuthenticateINBrowser = Property (#const GSASL_OPENID20_AUTHENTICATE_IN_BROWSER)
pattern PropertyValidateSimple                = Property (#const GSASL_VALIDATE_SIMPLE)
pattern PropertyValidateExternal              = Property (#const GSASL_VALIDATE_EXTERNAL)
pattern PropertyValidateAnonymous             = Property (#const GSASL_VALIDATE_ANONYMOUS)
pattern PropertyValidateGssapi                = Property (#const GSASL_VALIDATE_GSSAPI)
pattern PropertyValidateSecurid               = Property (#const GSASL_VALIDATE_SECURID)
pattern PropertyValidateSaml20                = Property (#const GSASL_VALIDATE_SAML20)
pattern PropertyValidateOpenid20              = Property (#const GSASL_VALIDATE_OPENID20)

-- libgsasl Callback function, in C style
type CallbackFn =
  GSaslContext -> GSaslSession -> Property -> IO CInt

-- Indicates if the current authentication is done or not
data Progress = GSaslDone | GSaslMore deriving (Eq, Show)
