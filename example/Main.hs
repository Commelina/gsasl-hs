module Main (main) where

import           Types
import           Exception
import           FFI

import           Foreign
import           Foreign.C

import Data.Char

main :: IO ()
main = do
  v <- gsasl_check_version nullPtr >>= peekCString
  print v

  withGSaslContext $ \ctx -> do
    getServerMechlist ctx >>= print
    isServerSupported ctx "PLAIN" >>= print
    isServerSupported ctx "SCRAM-SHA-256" >>= print
    isServerSupported ctx "SCRAM-SHA-512" >>= print

    setCallback ctx (\p s -> case p of
      PropertyHostname -> do
        setProperty s PropertyHostname "localhost"
        print $ "set hostname to localhost"
      PropertyValidateSimple -> do
        u <- getProperty s PropertyAuthid
        p <- getProperty s PropertyPassword
        print $ ">>> u=" <> u <> ", p=" <> p
        error "xxx"
      _ -> return ()
                    )

    withServerSession ctx "PLAIN" $ \session -> do
      mechName <- serverSessionMechanism session
      print $ "I am using mech: " <> mechName

      getProperty session PropertyHostname >>= print
      getPropertyFast session PropertyHostname >>= print

      doCallback ctx session PropertyHostname
      doCallback ctx session PropertyHostname
      doCallback ctx session PropertyHostname

      let e = GSaslErrCode 0
      print e
      print e

      print $ "toBase64 [the quick brown fox jumps over the lazy dog]: " <>
              toBase64 "the quick brown fox jumps over the lazy dog"

      serverStep session ("aa" <> [chr 0] <> "bb" <> [chr 0] <> "cc") >>= print
