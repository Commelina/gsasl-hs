{-# LANGUAGE CPP               #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms   #-}

module Network.SASL.Internal.FFI
  ( -- * Version
    Version
  , gsaslCheckVersion
    -- * Context
  , withGSaslContext
    -- * Mechanism
  , getServerMechlist
  , isServerSupported
    -- * Session
  , withServerSession
  , serverSessionMechanism
    -- * Property
  , getProperty
  , getPropertyFast
  , setProperty
    -- * Callback
  , setCallback
  , doCallback
    -- * Server Run
  , serverStep
  , serverStep64
   -- * Hashing and Crypto
  , toBase64
  , fromBase64
  , scramSecretsFromPasswordSha256
  , scramSecretsFromSaltedPasswordSha256
  ) where

#include <gsasl.h>

import           Network.SASL.Internal.Exception
import           Network.SASL.Internal.Types

import qualified Control.Exception               as E
import qualified Data.ByteString                 as B
import qualified Data.ByteString.Unsafe          as B
import           Data.Maybe                      (fromMaybe)
import           Foreign
import           Foreign.C
import           System.IO.Unsafe

-------------------------------------------------------------------------------
-- libgsasl Context
-------------------------------------------------------------------------------
foreign import ccall unsafe "gsasl.h gsasl_init"
  gsasl_init :: Ptr GSaslContext -> IO CInt

foreign import ccall unsafe "gsasl.h gsasl_done"
  gsasl_done :: GSaslContext -> IO ()

foreign import ccall unsafe "gsasl.h gsasl_check_version"
  gsasl_check_version :: CString -> IO CString

-- | The GNU SASL Library version
type Version = B.ByteString

-- | Check the library is at minimum the one given and return the actual library
--   version.
--   NOTE: This function can be called before a successful init.
--   input: the version string to compare with. Such as "1.10.0". If 'Nothing'
--          is passed, no check is done and only the version is returned.
--   output: the actual version string, or 'Nothing' if the condition is not met.
gsaslCheckVersion :: Maybe Version -> IO (Maybe Version)
gsaslCheckVersion req_ver_m = do
  let req_ver = fromMaybe "" req_ver_m
  B.useAsCString req_ver $ \cstr -> do
    res <- gsasl_check_version cstr
    if res == nullPtr then
       pure Nothing else
       Just <$> (B.unsafePackCString res)

-- | Initialize the GNU SASL Library, do an action with the context and free
--   the context after finishing it or if an exception is thrown.
--   [WARNING]: NEVER return the memory related to the context because it will
--              be freed after the action.
withGSaslContext :: (GSaslContext -> IO a) -> IO a
withGSaslContext action = E.bracket initCtx freeCtx action
  where initCtx = alloca $ \(p :: Ptr GSaslContext) ->
                    gsasl_init p >>= gsaslThen (peek p)
        freeCtx = gsasl_done

-------------------------------------------------------------------------------
-- libgsasl Mechanism
-------------------------------------------------------------------------------
foreign import ccall unsafe "gsasl.h gsasl_server_mechlist"
  gsasl_server_mechlist :: GSaslContext -> Ptr CString -> IO CInt

-- | Get the list of mechanisms supported by the server, seperated by space.
--  [WARNING]: the memory is allocated by the libgsasl and should be freed by
--             the caller. So we use 'unsafePackMallocCString' to attach a
--             finalizer to free the memory.
getServerMechlist :: GSaslContext -> IO B.ByteString
getServerMechlist ctx = alloca $ \(p :: Ptr CString) -> do
  errCode <- gsasl_server_mechlist ctx p
  cstr    <- peek p
  gsaslThen (B.unsafePackMallocCString cstr) errCode

foreign import ccall unsafe "gsasl.h gsasl_server_support_p"
  gsasl_server_support_p :: GSaslContext -> CString -> IO CInt

-- | Decide whether the server supports the given mechanism.
isServerSupported :: GSaslContext -> B.ByteString -> IO Bool
isServerSupported ctx mech = B.useAsCString mech $ \cstr -> do
  gsasl_server_support_p ctx cstr >>= \case
    1 -> return True
    _ -> return False

-------------------------------------------------------------------------------
-- libgsasl Session
-------------------------------------------------------------------------------
foreign import ccall unsafe "gsasl.h gsasl_server_start"
  gsasl_server_start :: GSaslContext -> CString -> Ptr GSaslSession -> IO CInt

foreign import ccall unsafe "gsasl.h gsasl_finish"
  gsasl_finish :: GSaslSession -> IO ()

-- | Initialize a server session with the given mechanism, do an action with
--   the session and free the session after finishing it or if an exception
--   is thrown. This function may throw 'GSaslException'.
--   [WARNING]: NEVER return the memory related to the session because it will
--              be freed after the action.
withServerSession :: GSaslContext -> B.ByteString -> (GSaslSession -> IO a) -> IO a
withServerSession ctx mech action = E.bracket initCtx freeCtx action
  where initCtx = B.useAsCString mech $ \cstr -> do
                    alloca $ \(p :: Ptr GSaslSession) ->
                      gsasl_server_start ctx cstr p >>= gsaslThen (peek p)
        freeCtx = gsasl_finish

foreign import ccall unsafe "gsasl.h gsasl_mechanism_name"
  gsasl_mechanism_name :: GSaslSession -> IO CString

-- | Get the mechanism name of the current session. Return 'Nothing' if it is
--   not known.
--   [WARNING]: the memory returned by the FFI call should [NEVER] be freed!!!
serverSessionMechanism :: GSaslSession -> IO (Maybe B.ByteString)
serverSessionMechanism session = do
  gsasl_mechanism_name session >>= \case
    cstr | cstr == nullPtr -> return Nothing
         | otherwise       -> Just <$> B.packCString cstr

-------------------------------------------------------------------------------
-- libgsasl Property
-------------------------------------------------------------------------------
foreign import ccall safe "gsasl.h gsasl_property_get"
  gsasl_property_get :: GSaslSession -> Property -> IO CString

-- | Get the property value of the current session. Return 'Nothing' if it is
--   unknown. This function may invoke the current callback.
--   [WARNING]: the memory returned by the FFI call should [NEVER] be freed!!!
getProperty :: GSaslSession -> Property -> IO (Maybe B.ByteString)
getProperty session prop = do
  gsasl_property_get session prop >>= \case
    cstr | cstr == nullPtr -> return Nothing
         | otherwise       -> Just <$> B.packCString cstr

foreign import ccall unsafe "gsasl.h gsasl_property_fast"
  gsasl_property_fast :: GSaslSession -> Property -> IO CString

-- | Get the property value of the current session. Return 'Nothing' if it is
--   unknown. This function will [NOT] invoke the current callback.
--   [WARNING]: the memory returned by the FFI call should [NEVER] be freed!!!
getPropertyFast :: GSaslSession -> Property -> IO (Maybe B.ByteString)
getPropertyFast session prop = do
  gsasl_property_fast session prop >>= \case
    cstr | cstr == nullPtr -> return Nothing
         | otherwise       -> Just <$> B.packCString cstr

foreign import ccall unsafe "gsasl.h gsasl_property_set"
  gsasl_property_set :: GSaslSession -> Property -> CString -> IO ()

foreign import ccall unsafe "gsasl.h gsasl_property_set_raw"
  gsasl_property_set_raw :: GSaslSession -> Property -> CString -> CSize -> IO ()

-- | Set the property value of the current session.
-- [WARNING]: the value passed to the FFI call is [COPIED] by the libgsasl.
setProperty :: GSaslSession -> Property -> B.ByteString -> IO ()
setProperty session prop val = B.unsafeUseAsCStringLen val $ \(cstr,len) ->
  gsasl_property_set_raw session prop cstr (fromIntegral len)

-------------------------------------------------------------------------------
-- libgsasl Callback
-------------------------------------------------------------------------------
foreign import ccall safe "wrapper"
  mkCallbackFnPtr :: CallbackFn -> IO (FunPtr CallbackFn)

foreign import ccall unsafe "gsasl.h gsasl_callback_set"
  gsasl_callback_set :: GSaslContext -> FunPtr CallbackFn -> IO ()

-- The function can invoke back to Haskell functions, so it should be safe.
foreign import ccall safe "gsasl.h gsasl_callback"
  gsasl_callback :: GSaslContext -> GSaslSession -> Property -> IO CInt

-- | Set the callback function of the current context.
-- [WARNING]: the context only keeps the pointer of the callback function, so
--            the it should be valid during the whole lifetime of the context.
setCallback :: GSaslContext -> (Property -> GSaslSession -> IO GSaslErrCode) -> IO ()
setCallback ctx cb = do
  -- FIXME: Here we catched all Haskell exceptions and return 'GSASL_AUTHENTICATION_ERROR'.
  --        However, this should be performed in the callback function.
  cbPtr <- mkCallbackFnPtr (\_ session prop -> E.handle (\(_ :: E.SomeException) ->
                                                            return (#const GSASL_AUTHENTICATION_ERROR)) $ do
                                 (GSaslErrCode n) <- cb prop session
                                 return n
                           )
  gsasl_callback_set ctx cbPtr

-- | Invoke the callback function with certain property. It throws 'GSASL_NO_CALLBACK'
--   if no callback is set.
--   Note that it will derive the context from the session if the context is NULL.
doCallback :: GSaslContext -> GSaslSession -> Property -> IO ()
doCallback ctx session prop =
  gsasl_callback ctx session prop >>= gsaslThen (return ())

--- server run
-- The function can invoke back to Haskell functions, so it should be safe.
foreign import ccall safe "gsasl.h gsasl_step"
  gsasl_step :: GSaslSession -> CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

-- | Perform one step of SASL authentication. It returns either 'GSaslDone' or
--   'GSaslMore' indicating the progress with the output, or throws an exception.
--   [WARNING]: see 'strFFIHelper' for the memory management.
serverStep :: GSaslSession -> B.ByteString -> IO (B.ByteString, Progress)
serverStep session input =
  strFFIHelper input (gsasl_step session) $ \output c ->
    case GSaslErrCode c of
      GSASL_OK   -> return (output, GSaslDone)
      NEEDS_MORE -> return (output, GSaslMore)
      e          -> E.throwIO (GSaslException e)

-- | Perform one step of SASL authentication. The input and output are both
--   encoded in base64. It returns either 'GSaslDone' or 'GSaslMore' indicating
--   the progress with the output, or throws an exception.
--   [WARNING]: The output is allocated by the libgsasl and
--              should be freed by the caller so we use 'unsafePackMallocCString'
--              to attach a finalizer to free the memory. See `Data.ByteString.Unsafe`
--              for more information.
serverStep64 :: GSaslSession -> B.ByteString -> IO (B.ByteString, Progress)
serverStep64 session input64 = do
  alloca $ \(p :: Ptr CString) -> do
    B.useAsCString input64 $ \cstr -> do
      c <- gsasl_step64 session cstr p
      case GSaslErrCode c of
        GSASL_OK -> do
          pOutput <- peek p
          output  <- B.unsafePackMallocCString pOutput
          return (output, GSaslDone)
        NEEDS_MORE -> do
          pOutput <- peek p
          output  <- B.unsafePackMallocCString pOutput
          return (output, GSaslMore)
        e -> E.throwIO (GSaslException e)

foreign import ccall safe "gsasl.h gsasl_step64"
  gsasl_step64 :: GSaslSession -> CString -> Ptr CString -> IO CInt

-------------------------------------------------------------------------------
-- Hashing and Crypto functions
-------------------------------------------------------------------------------
foreign import ccall unsafe "gsasl.h gsasl_base64_to"
  gsasl_base64_to :: CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

foreign import ccall unsafe "gsasl.h gsasl_base64_from"
  gsasl_base64_from :: CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

-- | Encode the input as base64.
--   [WARNING]: the output is allocated by the libgsasl and should be freed by
--              the caller. See 'strFFIHelper' for more information.
toBase64 :: B.ByteString -> B.ByteString
toBase64 input = unsafePerformIO $
  strFFIHelper input gsasl_base64_to $ \output c ->
    gsaslThen (return output) c

-- | Decode base64 data.
--   [WARNING]: the output is allocated by the libgsasl and should be freed by
--              the caller. See 'strFFIHelper' for more information.
fromBase64 :: B.ByteString -> B.ByteString
fromBase64 input = unsafePerformIO $
  strFFIHelper input gsasl_base64_from $ \output c ->
    gsaslThen (return output) c

-- | The C-style string-in and string-out function type.
type StrFFIFunc = CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

-- | Helper function for invoking a C-style string-in and string-out function.
--   [WARNING]: The output is allocated by the libgsasl and
--              should be freed by the caller so we use 'unsafePackMallocCString'
--              to attach a finalizer to free the memory. See `Data.ByteString.Unsafe`
--              for more information.
strFFIHelper :: B.ByteString -> StrFFIFunc -> (B.ByteString -> CInt -> IO a) -> IO a
strFFIHelper input f action = do
  B.useAsCStringLen input $ \(cstr,len) -> do
    alloca $ \(p :: Ptr CString) -> do
      alloca $ \(s :: Ptr CSize) -> do
        e       <- f cstr (fromIntegral len) p s
        pOutput <- peek p
        size    <- peek s
        output  <- B.unsafePackMallocCStringLen (pOutput, fromIntegral size)
        action output e

-- WARNING: unlike other functions, the 'char *'s are pre-allocaed by user.
foreign import ccall "gsasl.h gsasl_scram_secrets_from_password"
  gsasl_scram_secrets_from_password :: CUInt -> CString -> CUInt -> CString  -> CSize -> CString -> CString -> CString -> CString -> IO CInt

-- FIXME: Use enum to support different hash algorithms.
-- FIXME: avoid an unnecessary memory copy.
-- | Derive SCRAM SaltedKey/ClientKey/ServerKey/StoredKey from password.
--   [WARNING]: unlike most of the other functions, the outputs are PRE-ALLOCATED
--              by the user and should have enough space to hold the result.
scramSecretsFromPasswordSha256 :: B.ByteString -- password
                               -> CUInt        -- iterations
                               -> B.ByteString -- salt
                               -> ( B.ByteString -- saltedPassword
                                  , B.ByteString -- clientKey
                                  , B.ByteString -- serverKey
                                  , B.ByteString -- storedKey
                                  )
scramSecretsFromPasswordSha256 pw iter salt = unsafePerformIO $
  B.useAsCString pw $ \pPw                   ->
  B.unsafeUseAsCStringLen salt $ \(pSalt, saltLen) ->
  allocaBytes 32 $ \saltedPasswordBuf ->
  allocaBytes 32 $ \clientKeyBuf      ->
  allocaBytes 32 $ \serverKeyBuf      ->
  allocaBytes 32 $ \storedKeyBuf      -> do
    -- FIXME: use enum 'GSASL_HASH_SHA256' instead of literal '3'
    gsasl_scram_secrets_from_password 3 pPw iter pSalt (fromIntegral saltLen)
                                                       saltedPasswordBuf
                                                       clientKeyBuf
                                                       serverKeyBuf
                                                       storedKeyBuf
                                                       >>= gsaslThen (do
      saltedPassword <- B.packCStringLen (saltedPasswordBuf, 32)
      clientKey      <- B.packCStringLen (clientKeyBuf     , 32)
      serverKey      <- B.packCStringLen (serverKeyBuf     , 32)
      storedKey      <- B.packCStringLen (storedKeyBuf     , 32)
      return (saltedPassword, clientKey, serverKey, storedKey)
                                                                     )

foreign import ccall "gsasl.h gsasl_scram_secrets_from_salted_password"
  gsasl_scram_secrets_from_salted_password :: CUInt -> CString -> CString -> CString -> CString -> IO CInt

scramSecretsFromSaltedPasswordSha256 :: B.ByteString -- saltedPassword
                                     -> ( B.ByteString -- clientKey
                                        , B.ByteString -- serverKey
                                        , B.ByteString -- storedKey
                                        )
scramSecretsFromSaltedPasswordSha256 saltedPassword = unsafePerformIO $
  B.useAsCString saltedPassword $ \pSpw ->
  allocaBytes 32 $ \clientKeyBuf ->
  allocaBytes 32 $ \serverKeyBuf ->
  allocaBytes 32 $ \storedKeyBuf -> do
    -- FIXME: use enum 'GSASL_HASH_SHA256' instead of literal '3'
    gsasl_scram_secrets_from_salted_password 3 pSpw clientKeyBuf serverKeyBuf storedKeyBuf
      >>= gsaslThen (do
        clientKey <- B.packCStringLen (clientKeyBuf, 32)
        serverKey <- B.packCStringLen (serverKeyBuf, 32)
        storedKey <- B.packCStringLen (storedKeyBuf, 32)
        return (clientKey, serverKey, storedKey)
                    )
