------------------------------------------------------------------------
-- |
-- Module      : WaiMiddlewareHmacAuthSpec
-- Description : Wai HMAC Auth Middleware Spec
-- Copyright   : (c) 2015 Christopher Reichert
-- License     : BSD3
-- Maintainer  : Christopher Reichert <creichert07@gmail.com>
-- Stability   : unstable
-- Portability : POSIX
--
--
-- TODO test corner clases
-- - test expired timestamp (set skew in settings)
-- - test missing headers
-- - timestamp modified
-- - resource modified
-- - changing up hashing algorithm somehow


{-# LANGUAGE OverloadedStrings #-}

module WaiMiddlewareHmacAuthSpec (
    spec
  ) where


import           Data.ByteString                 (ByteString)
import           Network.HTTP.Types              (status200, HeaderName)
import           Network.Wai
import           Network.Wai.Test
import           Test.Hspec
import           Test.HUnit                      hiding (Test)

import           Network.Wai.Middleware.HmacAuth



-- | Simple Hmac Authentication Spec
spec :: Spec
spec = describe "Network.Wai.Middleware.HmacAuth" $ do
    it "authenticates valid signatures" caseHmacAuth
    it "rejects invalid secrets"        caseHmacInvalidSecret
    it "rejects invalid signatures"     caseHmacInvalidSignature
    it "rejects invalid headers"        caseHmacInvalidHeader
    it "rejects method modificatied"    caseHmacMethodModified
    it "rejects request path modified"  caseHmacPathModified



-- | Simple Hmac Middleware App
--
-- This app has preloaded api keys to simulate
-- some database or service which can access the
-- private keys.
hmacAuthApp :: HmacAuthSettings alg -> Application
hmacAuthApp stgs = hmacAuth lookupSecret stgs
                       $ \_ f -> f response
  where
    payload               = "{ \"api\", \"return data\" }"
    response              = responseLBS status200 [] payload
    -- Server-Side Api Credentials
    lookupSecret key      = return $ case lookup key creds of
                                       Nothing -> Nothing
                                       Just  s -> Just (Secret s)
    creds                 = [ (Key "key1", "secret1")
                            , (Key "key2", "secret2")
                            ]


-- defaults
key1, key2 :: ByteString
key1 = "key1"
key2 = "key2"

sec1 :: Secret
sec1 = Secret "secret1"

-- api key and secret shared in advance

timestamp   :: ByteString
timestamp    = "2015-01-01T00:00:00Z"


cfg :: HmacAuthSettings SHA512
cfg = defaultHmacAuthSettings


headers     :: [(HeaderName, ByteString)]
headers      = [ ("Content-Type", "application/json")
               , ("x-auth-timestamp", timestamp)
               ]

hmacReq     :: Request
hmacReq      = defaultRequest
               { requestMethod  = "GET"
               , rawPathInfo    = "/resource"
               , requestHeaders = headers
               }



-- | Test Hmac Authentication
caseHmacAuth :: Assertion
caseHmacAuth = do

    -- valid signature
    validSignatureReq   <- signRequest cfg (Secret "secret1") hmacReq
                           { requestHeaders = ("x-auth-key", key1)
                                                : headers
                           }


    -- test hmac authenticaation
    flip runSession (hmacAuthApp defaultHmacAuthSettings) $ do

        res <- request validSignatureReq

        -- Succesful verification
        assertStatus 200 res

        -- succesfully authentication request
        assertBody "{ \"api\", \"return data\" }" res



--  |
caseHmacInvalidSecret :: Assertion
caseHmacInvalidSecret = do
    invalidSecretReq <- signRequest cfg sec1 hmacReq
                          { requestHeaders = ("x-auth-key", key2)
                                               : headers
                          }

    flip runSession (hmacAuthApp defaultHmacAuthSettings) $
        request invalidSecretReq
          >>= assertStatus 401



-- | Invalid signatures are rejected
caseHmacInvalidSignature :: Assertion
caseHmacInvalidSignature = do
    -- test hmac authenticaation
    -- invalid secret
    invalidSignatureReq <- signRequest cfg (Secret "wJalrXUtnFEMI") hmacReq
                           { requestHeaders = ("x-auth-key", key1)
                                                : headers
                           }

    flip runSession (hmacAuthApp defaultHmacAuthSettings) $
        request invalidSignatureReq
          >>= assertStatus 401


caseHmacInvalidHeader :: Assertion
caseHmacInvalidHeader = do
    -- invalid headers
    invalidHeaderReq    <- signRequest cfg sec1 hmacReq
    -- test hmac authenticaation
    flip runSession (hmacAuthApp defaultHmacAuthSettings) $
        request invalidHeaderReq
          >>= assertStatus 401



caseHmacMethodModified :: Assertion
caseHmacMethodModified = do
    req <- signRequest cfg sec1 hmacReq
    flip runSession (hmacAuthApp defaultHmacAuthSettings) $
        -- reject request path modified after signature
        request req { rawPathInfo = "/etc/passwd" }
          >>= assertStatus 401



caseHmacPathModified :: Assertion
caseHmacPathModified =  do
    req <- signRequest cfg sec1 hmacReq
    -- test hmac authenticaation
    flip runSession (hmacAuthApp defaultHmacAuthSettings) $
      -- reject request path modified after signature
      request req { rawPathInfo = "/etc/passwd" }
        >>= assertStatus 401
