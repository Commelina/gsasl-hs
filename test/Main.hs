{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as BSC
import           Data.Functor
import           Data.List
import           Data.Maybe
import           Data.Ord
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC

import           Network.SASL.SASL

main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [ properties
                          , unitTest1
                          ]
properties :: TestTree
properties = testGroup "Properties" [qcProps]

qcProps = testGroup "(checked by QuickCheck)"
  [ QC.testProperty "..." $
      \c n -> (n :: Int) <= 50 QC.==>
        let str = B.replicate n (c :: Word8)
         in fromBase64 (toBase64 str) == str
  ]

unitTest1 = testGroup "Version Check"
  [ testCase "check version with NULL" $
      (gsaslCheckVersion Nothing <&> isValidVersion) @? "Invalid libgsasl version"
  , testCase "check version with a small version" $
      (gsaslCheckVersion (Just "0.2.0") <&> isValidVersion) @? "Invalid libgsasl version"
  , testCase "check version with a large version" $
      (gsaslCheckVersion (Just "9.9.9") <&> isNothing) @? "Invalid libgsasl version"
  ]
  where isValidVersion :: Maybe B.ByteString -> Bool
        isValidVersion Nothing = False
        isValidVersion (Just s) =
          let vs = B.split (fromIntegral $ fromEnum '.') s
           in length vs == 3 &&
              cmp (read $ BSC.unpack $ vs !! 0)
                  (read $ BSC.unpack $ vs !! 1)
                  (read $ BSC.unpack $ vs !! 2)
          where cmp a b c
                    | a > 1     = True
                    | b > 10    = True
                    | c >= 0    = True
                    | otherwise = False
