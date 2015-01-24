-----------------------------------------------------------------------------
-- |
-- Module      : Network.Wai.Middleware.HmacAuth
-- Description : WAI HMAC Authentication Middleware
-- Copyright   : (c) 2015 Christopher Reichert
-- License     : BSD3
-- Maintainer  : Christopher Reichert <creichert07@gmail.com>
-- Stability   : experimental
-- Portability : POSIX
--

{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}


module Network.Wai.Middleware.HmacAuth (

      -- * Middleware functionality
      hmacAuth

      -- * Crypto
    , signRequest

      -- ** Supported Hashing Algorithms
    , HashAlgorithm
    , SHA512, SHA256, SHA1, MD5

      -- * Hmac and Middleware Configuration
    , HmacAuthSettings (..)
    , HmacStrategy (..)
    , defaultHmacAuthSettings

    , Secret (..)
    , Key (..)
    ) where


import           Control.Monad          (when)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Crypto.Hash
import           Crypto.Hash.MD5        as MD5
import           Data.Byteable          (toBytes)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base64 as BS64
import           Data.CaseInsensitive   (CI)
import           Data.Maybe             (fromMaybe)
import           Data.Monoid            ((<>))
import           Data.Word8             (isSpace, toLower, _colon)
import qualified Network.HTTP.Types     as Http
import           Network.Wai



-- | Various settings for HMAC authentication
data HmacAuthSettings alg = HmacAuthSettings
    {
      -- | We can leave these empty and use the data
      -- alread in the headers
      authKeyHeader       :: !(CI ByteString)

      -- | Name of the HTTP Header which carries the timestamp
    , authTimestampHeader :: !(CI ByteString)

      -- | Is the route protected?
    , authIsProtected     :: !(Request -> IO Bool)

      -- | On no auth sign a message for the client
    , authOnNoAuth        :: !(HmacAuthException -> Application)

      -- | HMAC signing algorithm
      --
      -- MD5, SHA1, SHA256, and SHA512 supported
    , authAlgorithm       :: alg

      -- | Realm provider.
      --
      -- Used to identify unique headers.
      --
      -- e.g. Authorization: API key:signature
    , authRealm           :: !ByteString

      -- | Use Header or GetParam spec.
      --
      -- GetParam is useful for sharing encoded URLs
      --
      -- TODO can it be both? e.g. list of supported
      --  strategies
    , authSpec            :: !HmacStrategy

      -- | Print debug output when signing Requests
    , authDebug           :: !Bool
    }



-- | HMAC Public Key
newtype Key = Key ByteString
              deriving (Eq, Show)



-- | HMAC Secret Key
newtype Secret = Secret ByteString
                 deriving (Eq, Show)



-- | Hmac requests can be accepted through GET params
-- or Http headers.
data HmacStrategy = Header
                    -- ^ Look for auth info in HTTP Headers
                    --- | Query
                    --- ^ Look for auth info in Query params
                    ---   Useful for encoding and sharing requests
                    ---   without the need for a specific client
                    deriving Show




-- | Possibilities for Error during an Hmac Authentication Session
data HmacAuthException
    = NoSecret
      -- ^ No secret could be found for the key
      -- in the request
    | NoAuthHeader
      -- ^ No specified Auth header found
    | InvalidSignature
      -- ^ Signature could not be decoded properly
    | SignatureMismatch
      -- ^ Valid signature which does not match
      -- server generated sig
    deriving Show




-- | Lookup the Secret for a Given Key
--
-- This is essentially a credentials provider so that the
-- middleware can generate a request signature for a given
-- request.
--
-- TODO this is a HACK up front but should be changed to not
-- expose the secret to the middleware.
type LookupSecret m = Key -> m (Maybe Secret)



-----------------------------------------------------------------------------
-----------------------------------------------------------------------------



-- | Perform Hmac authentication.
--
-- Uses a lookup function to retrieve the secret used to sign
-- the incoming request.
--
-- > let lookupSecret key = case key of
-- >                          "client" -> Just (Secret "secretkey")
-- >                          _        -> Nothing
-- >      authware = hmacAuth lookupSecret defaultHmacAuth
-- > Warp.run (read port) $ authware $ app
--
hmacAuth :: forall alg .
            HashAlgorithm alg
            => LookupSecret IO
            -> HmacAuthSettings alg
            -> Application
            -> Request
            -> (Response -> IO ResponseReceived)
            -> IO ResponseReceived
hmacAuth lookupSecret cfg@HmacAuthSettings {..} app req respond = do

    isProtected <- authIsProtected req

    allowed     <- if isProtected
                      then check
                      else return $ Right ()

    case allowed of
      Left e  -> authOnNoAuth e req respond
      Right _ -> app req respond

  where
    check =
      case lookup "Authorization" $ requestHeaders req of
        Nothing -> return $ Left NoAuthHeader
        Just bs ->
          let (d, rest)        = BS.break isSpace bs
              isColon          = (==) _colon
              (key, signature) = BS.break isColon rest
          in if BS.map toLower d == BS.map toLower authRealm
               then checkB64 key signature
               else return $ Left InvalidSignature

    checkB64 key sig' = case BS.uncons sig' of
      Nothing             -> return $ Left InvalidSignature
      Just (_, signature) -> do

        moursecret <- lookupSecret $ Key $ BS.tail key

        case moursecret of
          Nothing        -> return $ Left NoSecret
          Just oursecret -> do

            ourreq <- signRequest cfg oursecret req

            let headers = requestHeaders ourreq
                oursig  = getBase64DecodedSignature cfg authRealm headers

            when authDebug $ sequence_
                [
                  print ("Server Key: " <> show key)
                , print ("Server Sig: " <> show oursig)
                , print ("Client Sig: " <> show signature)
                ]

            case oursig of
              Left e    -> return $ Left e
              Right sig -> return $ checkSig sig signature

    -- TODO effects of timing attack on string comparison?
    -- TODO Compare encoded or decoded signature
    -- sigs must match
    checkSig oursig theirsig = if oursig == theirsig
                                 then Right ()
                                 else Left SignatureMismatch



-- | Default HMAC authentication settings
--
-- Uses SHA512 as default signing algorithm
--
-- @authOnNoAuth@ responds with:
-- @
--   WWW-Authenticate: Realm="" HMAC-MD5;HMAC-SHA1;HMAC-SHA256;HMAC-SHA512"
--   [...]
--   Provide valid credentials
-- @
--
defaultHmacAuthSettings :: HmacAuthSettings SHA512
defaultHmacAuthSettings = HmacAuthSettings
    { authRealm           = "Hmac"
    , authKeyHeader       = "X-auth-key"
    , authTimestampHeader = "X-auth-timestamp"
    , authOnNoAuth        = defUnauthorized
    , authIsProtected     = const $ return True
    , authSpec            = Header
    , authAlgorithm       = SHA512
    , authDebug           = True
    }
  where
    defNoAuthHeader =
      ("WWW-Authenticate", BS.concat
              [ "Realm=\"\" "  -- TODO default realm
              ,  "HMAC-MD5;HMAC-SHA1;HMAC-SHA256;HMAC-SHA512"
              ])
    -- TODO negotiate the alg
    defUnauthorized _ _req f = f $ responseLBS
        Http.status401
        (defNoAuthHeader : requestHeaders _req)
        "Provide valid credentials"



-----------------------------------------------------------------------------
-----------------------------------------------------------------------------



-- | Decode the signature in the Authorization header.
--
getBase64DecodedSignature
  :: HmacAuthSettings alg
     -> ByteString
     -> [(CI ByteString, ByteString)]  -- ^ headers to search for sig
     -> Either HmacAuthException ByteString
getBase64DecodedSignature HmacAuthSettings{..} realm headers =
  case lookup "Authorization" headers of
    Nothing -> Left InvalidSignature
    Just bs ->
      let (r, rest)   = BS.break isSpace bs
          isColon     = (==) _colon
          (_, sig') = BS.break isColon rest
      in if BS.map toLower r == BS.map toLower realm
           then case BS.uncons sig' of
                  Nothing         -> Left InvalidSignature
                  Just (_, sig'') -> Right sig''
           else Left InvalidSignature



-- | Sign a request using HMAC
--
-- signature = base64( hmac-sha1 (key, utf8( stringtosign )  ) )
--
-- TODO hash contents throught MonadState using a type to make
-- sure all the components are there or err.
signRequest :: forall m alg .
               (
                  MonadIO m
                , HashAlgorithm alg )
               => HmacAuthSettings alg
               -> Secret
               -> Request
               -> m Request
signRequest cfg@HmacAuthSettings{..} (Secret secret) req = do

    body <- liftIO $ requestBody req

    let contentmd5    = MD5.hash body
        res           = canonicalizedResource req
        payload       = buildMessage verb contentmd5 ctype date res
        HMAC hashed   = hmac secret payload :: HMAC alg
        digest        = BS64.encode (toBytes hashed)

    return $ req { requestHeaders =
                      authHeader cfg (Key key) (Secret digest)
                        : requestHeaders req
                 }
  where
    -- peices of signature
    maybeHeader = fromMaybe "" . flip lookup (requestHeaders req)
    verb        = requestMethod req
    ctype       = maybeHeader Http.hContentType
    -- TODO use real timestamp and test difference
    date        = maybeHeader authTimestampHeader
    -- BUG taking entire header instead of just key
    key         = maybeHeader authKeyHeader



-- | TODO readert
authHeader :: HmacAuthSettings alg
              -> Key
              -> Secret
              -> (CI ByteString, ByteString)
authHeader HmacAuthSettings{..} (Key key) (Secret sig) =
    let auth = BS.concat [ authRealm, " ", key, ":", sig ]
    in ("Authorization", auth)



-- | Build the string to be HMAC signed
--
-- @
-- stringtosign = http-method  + "\n" +
-- 	          content md5  + "\n" +
-- 	          content-type + "\n" +
-- 	          date         + "\n" +
-- 	          canonicalizedUri;
-- @
buildMessage :: Http.Method    -- ^ HTTP Method
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
canonicalizedResource :: Request -> ByteString
canonicalizedResource req =
    let uri = rawPathInfo req
    in BS.concat [ uri ]
