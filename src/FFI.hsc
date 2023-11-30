{-# LANGUAGE CApiFFI         #-}
{-# LANGUAGE CPP             #-}
{-# LANGUAGE LambdaCase      #-}
{-# LANGUAGE PatternSynonyms #-}

module FFI where

#include <gsasl.h>

import           Exception
import           Types

import qualified Control.Exception      as E
import qualified Data.ByteString        as B
import qualified Data.ByteString.Unsafe as B
import           Foreign
import           Foreign.C
import           System.IO.Unsafe

--- context
foreign import ccall unsafe "gsasl.h gsasl_init"
  gsasl_init :: Ptr GSaslContext -> IO CInt

foreign import ccall unsafe "gsasl.h gsasl_done"
  gsasl_done :: GSaslContext -> IO ()

foreign import ccall unsafe "gsasl.h gsasl_check_version"
  gsasl_check_version :: CString -> IO CString

withGSaslContext :: (GSaslContext -> IO a) -> IO a
withGSaslContext action = do
  alloca $ \(p :: Ptr GSaslContext) -> do
    gsasl_init p >>= \case
      0 -> do
        ctx <- peek p
        x <- action ctx
        gsasl_done ctx
        return x
      _ -> error "gsasl_init failed"

--- mech
foreign import ccall unsafe "gsasl.h gsasl_server_mechlist"
  gsasl_server_mechlist :: GSaslContext -> Ptr CString -> IO CInt

getServerMechlist :: GSaslContext -> IO String
getServerMechlist ctx = alloca $ \(p :: Ptr CString) -> do
  gsasl_server_mechlist ctx p >>= \case
    0 -> do
      peek p >>= peekCString
    _ -> error "gsasl_server_mechlist failed"

foreign import ccall unsafe "gsasl.h gsasl_server_support_p"
  gsasl_server_support_p :: GSaslContext -> CString -> IO CInt

isServerSupported :: GSaslContext -> String -> IO Bool
isServerSupported ctx mech = withCString mech $ \cstr -> do
  gsasl_server_support_p ctx cstr >>= \case
    1 -> return True
    _ -> return False

--- session
foreign import ccall unsafe "gsasl.h gsasl_server_start"
  gsasl_server_start :: GSaslContext -> CString -> Ptr GSaslSession -> IO CInt

foreign import ccall unsafe "gsasl.h gsasl_finish"
  gsasl_finish :: GSaslSession -> IO ()

withServerSession :: GSaslContext -> String -> (GSaslSession -> IO a) -> IO a
withServerSession ctx mech action = withCString mech $ \cstr -> do
  alloca $ \(p :: Ptr GSaslSession) -> do
    gsasl_server_start ctx cstr p >>= \case
      0 -> do
        session <- peek p
        x <- action session
        gsasl_finish session
        return x
      _ -> error "gsasl_server_start failed"

foreign import ccall unsafe "gsasl.h gsasl_mechanism_name"
  gsasl_mechanism_name :: GSaslSession -> IO CString

serverSessionMechanism :: GSaslSession -> IO String
serverSessionMechanism session =
  peekCString =<< gsasl_mechanism_name session

--- property
foreign import ccall safe "gsasl.h gsasl_property_get"
  gsasl_property_get :: GSaslSession -> Property -> IO CString

getProperty :: GSaslSession -> Property -> IO String
getProperty session prop = peekCString =<< gsasl_property_get session prop

foreign import ccall unsafe "gsasl.h gsasl_property_fast"
  gsasl_property_fast :: GSaslSession -> Property -> IO CString

getPropertyFast :: GSaslSession -> Property -> IO String
getPropertyFast session prop = peekCString =<< gsasl_property_fast session prop

foreign import ccall unsafe "gsasl.h gsasl_property_set"
  gsasl_property_set :: GSaslSession -> Property -> CString -> IO ()

setProperty :: GSaslSession -> Property -> String -> IO ()
setProperty session prop val = withCString val $ gsasl_property_set session prop

--- callback
foreign import ccall "wrapper"
  mkCallbackFnPtr :: CallbackFn -> IO (FunPtr CallbackFn)

foreign import ccall unsafe "gsasl.h gsasl_callback_set"
  gsasl_callback_set :: GSaslContext -> FunPtr CallbackFn -> IO ()

foreign import ccall safe "gsasl.h gsasl_callback"
  gsasl_callback :: GSaslContext -> GSaslSession -> Property -> IO CInt

setCallback :: GSaslContext -> (Property -> GSaslSession -> IO ()) -> IO ()
setCallback ctx cb = do
  cbPtr <- mkCallbackFnPtr (\_ session prop -> cb prop session >> return 0)
  gsasl_callback_set ctx cbPtr

doCallback :: GSaslContext -> GSaslSession -> Property -> IO ()
doCallback ctx session prop = gsasl_callback ctx session prop >> return ()

--- server run
foreign import ccall safe "gsasl.h gsasl_step"
  gsasl_step :: GSaslSession -> CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

serverStep :: GSaslSession -> String -> IO (String, Bool)
serverStep session input =
  helper input (gsasl_step session) $ \output c ->
    case GSaslErrCode c of
      GSASL_OK   -> return (output, True)
      NEEDS_MORE -> return (output, False)
      e          -> E.throwIO (GSaslException e)

foreign import ccall safe "gsasl.h gsasl_step64"
  gsasl_step64 :: GSaslSession -> CString -> Ptr CString -> IO CInt

--- crypto
foreign import ccall unsafe "gsasl.h gsasl_base64_to"
  gsasl_base64_to :: CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

foreign import ccall unsafe "gsasl.h gsasl_base64_from"
  gsasl_base64_from :: CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt

toBase64 :: String -> String
toBase64 input = unsafePerformIO $
  helper input gsasl_base64_to $ \output c ->
    case GSaslErrCode c of
      GSASL_OK -> return output
      e        -> E.throwIO (GSaslException e)
{-# NOINLINE toBase64 #-}

fromBase64 :: String -> String
fromBase64 input = unsafePerformIO $
  helper input gsasl_base64_from $ \output c ->
    case GSaslErrCode c of
      GSASL_OK -> return output
      e        -> E.throwIO (GSaslException e)
{-# NOINLINE fromBase64 #-}

type StrFFIFunc = CString -> CSize -> Ptr CString -> Ptr CSize -> IO CInt
helper :: String -> StrFFIFunc -> (String -> CInt -> IO a) -> IO a
helper input f action = do
  withCStringLen input $ \(cstr,len) -> do
    alloca $ \(p :: Ptr CString) -> do
      alloca $ \(s :: Ptr CSize) -> do
        e <- f cstr (fromIntegral len) p s
        pOutput <- peek p
        size <- peek s
        output <- peekCStringLen (pOutput, fromIntegral size)
        gsasl_free pOutput -- Note: it is the caller's responsibility to free the memory
        action output e


--- scram
-- WARNING: unlike other functions, the 'char *'s are pre-allocaed by user.
foreign import ccall "gsasl.h gsasl_scram_secrets_from_password"
  gsasl_scram_secrets_from_password :: CUInt -> CString -> CUInt -> CString  -> CSize -> CString -> CString -> CString -> CString -> IO CInt

scramSecretsFromPasswordSha256 :: B.ByteString -- password
                               -> CUInt      -- iterations
                               -> B.ByteString -- salt
                               -> ( B.ByteString -- saltedPassword
                                  , B.ByteString -- clientKey
                                  , B.ByteString -- serverKey
                                  , B.ByteString -- storedKey
                                  )
scramSecretsFromPasswordSha256 pw iter salt = unsafePerformIO $
  B.unsafeUseAsCStringLen pw $ \(pPw, pwLen) ->
  B.unsafeUseAsCStringLen salt $ \(pSalt, saltLen) ->
  allocaBytes 32 $ \saltedPasswordBuf ->
  allocaBytes 32 $ \clientKeyBuf ->
  allocaBytes 32 $ \serverKeyBuf ->
  allocaBytes 32 $ \storedKeyBuf -> do
  gsasl_scram_secrets_from_password 3 pPw iter pSalt (fromIntegral saltLen) saltedPasswordBuf clientKeyBuf serverKeyBuf storedKeyBuf >>= checkRC
  saltedPassword <- B.packCStringLen (saltedPasswordBuf, 32)
  clientKey <- B.packCStringLen (clientKeyBuf, 32)
  serverKey <- B.packCStringLen (serverKeyBuf, 32)
  storedKey <- B.packCStringLen (storedKeyBuf, 32)
  return (saltedPassword, clientKey, serverKey, storedKey)
  where
    checkRC c = case GSaslErrCode c of
                  GSASL_OK -> return ()
                  e        -> E.throwIO (GSaslException e)

--- misc
foreign import ccall unsafe "gsasl.h gsasl_free"
  gsasl_free :: Ptr a -> IO ()
