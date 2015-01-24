------------------------------------------------------------------------
-- |
-- Module      : Hpc
-- Description : Rets Hpc Code Coverage
-- Copyright   : (c) 2014 Christopher Reichert
-- License     : AllRightsReserved
-- Maintainer  : Christopher Reichert <creichert@reichertbrothers.com>
-- Stability   : unstable
-- Portability : GNU/Linux, FreeBSD
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


expected :: Fractional a => a
-- expected = 90
expected = 10



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
                                -- Hpc seems to have trouble with multiple Main
                                -- target in the cabal file
                                -- , "dist/hpc/tix/rets-0.1.0.0/rets-0.1.0.0.tix"
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
