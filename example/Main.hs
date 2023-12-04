{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Network.SASL.SASL

import qualified Data.ByteString as B

main :: IO ()
main = do
  gsaslCheckVersion Nothing        >>= print
  gsaslCheckVersion (Just "1.0.0") >>= print
  gsaslCheckVersion (Just "9.9.9") >>= print

  withGSaslContext $ \ctx -> do
    getServerMechlist ctx >>= print
    getServerMechlist ctx >>= print
    getServerMechlist ctx >>= print
    isServerSupported ctx "PLAIN" >>= print
    isServerSupported ctx "SCRAM-SHA-256" >>= print
    isServerSupported ctx "SCRAM-SHA-512" >>= print

    setCallback ctx (\p s -> case p of
      PropertyHostname -> do
        setProperty s PropertyHostname "localhost"
        putStrLn $ "set hostname to localhost"
      PropertyValidateSimple -> do
        u <- getProperty s PropertyAuthid
        p_ <- getProperty s PropertyPassword
        putStrLn $ ">>> u=" <> show u <> ", p=" <> show p_
        error "xxx"
      _ -> return ()
                    )

    withServerSession ctx "PLAIN" $ \session -> do
      mechName <- serverSessionMechanism session
      print $ "I am using mech: " <> show mechName

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

      serverStep session ("aa" <> B.singleton 0 <> "bb" <> B.singleton 0 <> "cc") >>= print
