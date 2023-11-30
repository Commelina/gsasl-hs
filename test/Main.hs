import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC
import           Test.Tasty.SmallCheck as SC

import           Data.List
import           Data.Ord

import           Exception
import           FFI
import           Types

main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [ properties
                          -- , unitTests
                          ]

properties :: TestTree
properties = testGroup "Properties" [scProps, qcProps]

scProps = testGroup "(checked by SmallCheck)"
  [ SC.testProperty "from . to == id" $
      \str -> fromBase64 (toBase64 (str :: String)) == str
  , SC.testProperty "..." $
      \c n -> (n :: Int) <= 10 SC.==>
        let str = replicate n (c :: Char)
         in fromBase64 (toBase64 str) == str
  -- the following property does not hold
{-
  , SC.testProperty "Fermat's last theorem" $
      \x y z n ->
        (n :: Integer) >= 3 SC.==> x^n + y^n /= (z^n :: Integer)
-}
  ]

qcProps = testGroup "(checked by QuickCheck)"
  [ QC.testProperty "from . to == id" $
      \str -> fromBase64 (toBase64 (str :: String)) == str
  -- the following property does not hold
{-
  , QC.testProperty "Fermat's last theorem" $
      \x y z n ->
        (n :: Integer) >= 3 QC.==> x^n + y^n /= (z^n :: Integer)
-}
  ]

{-
unitTests = testGroup "Unit tests"
  [ testCase "List comparison (different length)" $
      [1, 2, 3] `compare` [1,2] @?= GT

  -- the following test does not hold
  , testCase "List comparison (same length)" $
      [1, 2, 3] `compare` [1,2,2] @?= LT
  ]
-}
