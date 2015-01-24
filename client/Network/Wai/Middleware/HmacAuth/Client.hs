-------------------------------------------------------------------------
-- |
-- Module      : Network.Wai.Middleware.HmacAuth.Client
-- Description : Wai HMAC Auth Middleware Client
-- Copyright   : (c) 2015 Christopher Reichert
-- License     : BSD3
-- Maintainer  : Christopher Reichert <creichert07@gmail.com>
-- Stability   : experimental
-- Portability : POSIX
--
-- Compatible with HTTP Client


{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}


module Network.Wai.Middleware.HmacAuth.Client
       (
         -- * Sign a 'Request' with HMAC
         applyHmacAuth

         -- * Settings
         --
         -- These correspond to the 'HmacAuthSettings' found
         -- in 'Network.WAI.Middleware.HmacAuth' with slightly
         -- less options. These should correlate when deploying.
         -- The 'defaultHmacAuthSettings' in both modules should
         -- be ready-to-use together.
       , defaultHmacAuthSettings
       , HmacAuthSettings (..)
       ) where



import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Crypto.Hash
import           Crypto.Hash.MD5        as MD5
import           Data.Byteable          (toBytes)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString.Base64 as BS64
import qualified Data.ByteString.Char8  as BS
import qualified Data.ByteString.Lazy   as B
import           Data.CaseInsensitive   (CI)
import           Data.Maybe             (fromMaybe)
import           Data.Time
import           Network.HTTP.Client
import qualified Network.HTTP.Types     as Http
import           System.Locale




-- | Various control settings for HMAC authentication
data HmacAuthSettings alg = HmacAuthSettings
    {
      authKeyHeader       :: !(CI ByteString)
    , authTimestampHeader :: !(CI ByteString)

      -- | HMAC signing algorithm
      --
      -- MD5, SHA1, SHA256, and SHA512 supported
    , authAlgorithm       :: alg

      -- | Realm provider.
      --
      -- e.g. Authorization: API key:signature
    , authRealm           :: !ByteString

      -- | Use Header or QueryParam spec.
      --
      -- Currently, only the @Header@ @Strategy@ is supported
    , authSpec            :: !Strategy
    }



data Strategy = Header
              -- ^ Use HTTP Header to authorize clients
              --- | Query
              --- ^ TODO Use query parameters (not yet supported)



type Secret = ByteString
type Key    = ByteString



-- | default HMAC client settings
defaultHmacAuthSettings :: HmacAuthSettings SHA512
defaultHmacAuthSettings = HmacAuthSettings
    { authRealm           = "Hmac"
    , authKeyHeader       = "X-auth-key"
    , authTimestampHeader = "X-auth-timestamp"
    , authSpec            = Header
    , authAlgorithm       = SHA512
    }



-- | Add an Hmac auth header, signed with the specified secret, to the
-- given Request. Ignore error handling:
--
-- > applyHmacAuth defaultHmacSettings "secret" $ fromJust $ parseUrl url
--
-- Since 0.1.0
applyHmacAuth :: forall m alg .
                 (
                   MonadIO m
                 , HashAlgorithm alg )
                 => HmacAuthSettings alg
                 -> Key
                 -> Secret
                 -> Request
                 -> m Request
applyHmacAuth settings key secret req = do

    now <- liftIO getCurrentTime

    let date                = timefmt now
        contentmd5          = MD5.hash $ B.toStrict body
        res                 = canonicalizedResource req
        payload             = buildMessage verb contentmd5 (ctype req) date res
        HMAC hashed         = signPayload secret payload
        digest              = BS64.encode (toBytes hashed)

    return $ req { requestHeaders =
                      [ ("X-auth-timestamp", date)
                      , ("X-auth-apikey",key)
                      , authHeader settings key digest
                      ] ++ requestHeaders req
                 }
  where
    signPayload :: Secret -> ByteString -> HMAC alg
    signPayload = hmac
    timefmt     = BS.pack . formatTime defaultTimeLocale "%FT%T"
    verb        = method req
    ctype       = fromMaybe "" . lookup Http.hContentType . requestHeaders
    body        = case requestBody req of
                    RequestBodyLBS lbs -> lbs
                    RequestBodyBS  bs  -> B.fromStrict bs
                    _                  -> error "RequestBody type Not Supported"




-----------------------------------------------------------------------------
-----------------------------------------------------------------------------



-- | Create HTTP Authorization header for the give key and signature.
authHeader :: HmacAuthSettings alg
              -> Key
              -> Secret
              -> (CI ByteString, ByteString)
authHeader HmacAuthSettings{..} key sig =
    let auth = BS.concat [ authRealm, " ", key, ":", sig ]
    in ("Authorization", auth)




-- | Prepare a string to be HMAC signed.
--
-- @
-- stringtosign = http-method  + "\n" +
-- 	          content md5  + "\n" +
-- 	          content-type + "\n" +
-- 	          date         + "\n" +
-- 	          canonicalizedUri;
-- @
--
buildMessage
  :: Http.Method    -- ^ HTTP Method
     -> ByteString  -- ^ md5 Checksum of the request body
     -> ByteString  -- ^ Content-Type
     -> ByteString  -- ^ Date header of the HTTP request
     -> ByteString  -- ^ Canonicalized request location
     -> ByteString  -- ^ Return the unencoded string to sign
buildMessage verb contentmd5 ctype date resource =
    BS.concat [ verb, "\n"
              , contentmd5, "\n"
              , ctype, "\n"
              , date, "\n"
              , resource
              ]



-- | Canonicalization of the request uri
--
-- http-request uri from the protocol name up to the query string.
-- TODO add the query string to the canonicalized resource?
canonicalizedResource :: Request -> ByteString
canonicalizedResource = path
