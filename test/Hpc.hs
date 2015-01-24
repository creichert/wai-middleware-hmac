------------------------------------------------------------------------
-- |
-- Module      : Hpc
-- Description : Hpc Code Coverage
-- Copyright   : (c) 2015 Christopher Reichert
-- License     : BSD3
-- Maintainer  : Christopher Reichert <creichert07@gmail.com>
-- Stability   : unstable
-- Portability : POSIX
--


module Main (main) where


import           Data.List        (genericLength)
import           Data.Maybe       (catMaybes)
import           System.Directory
import           System.Exit      (exitFailure, exitSuccess)
import           System.Process   (readProcess)
import           Text.Regex       (matchRegex, mkRegex)


average :: (Fractional a, Real b) => [b] -> a
average xs = realToFrac (sum xs) / genericLength xs


expected :: Double
expected = 90.0



-- | There are lots of caveats for using this as a test.
--
-- That said, here are a list of reasons to use this:
--
-- TODO:
--   1) report for each cabal target
main :: IO ()
main = do
  -- this will have to be don for each target
  createDirectoryIfMissing True "dist/doc/html/hpc/mix/spec/"
  output <- readProcess "hpc" [ "report"
                              , "--per-module"
                              , "--hpcdir", "dist/hpc/vanilla/mix/spec/"
                              , "dist/hpc/vanilla/tix/spec/spec.tix"
                              ] ""


  _ <- readProcess "hpc" [ "markup"
                         , "--hpcdir", "dist/hpc/vanilla/mix/spec/"
                         , "--destdir", "dist/doc/html/hpc/spec/"
                         , "dist/hpc/vanilla/tix/spec/spec.tix"
                         ] ""


  if average (match output) >= expected
    then exitSuccess
    else putStr output >> exitFailure



match :: String -> [Int]
match = fmap read . concat . catMaybes . fmap (matchRegex pattern) . lines
  where
    pattern = mkRegex "^ *([0-9]*)% "
