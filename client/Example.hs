

{-# LANGUAGE OverloadedStrings #-}


import qualified Network.HTTP.Client                    as H
import           Network.Wai.Middleware.HmacAuth.Client



main :: IO ()
main = do
    request <- H.parseUrl "http://localhost:3000/somewhere"
                 >>= applyHmacAuth defaultHmacAuthSettings "key" "secret"

    H.withManager H.defaultManagerSettings $ \manager -> do
        response <- H.httpLbs request manager
        print $ H.responseBody response
