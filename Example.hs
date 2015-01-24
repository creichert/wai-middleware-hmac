
{-# LANGUAGE OverloadedStrings #-}

import           Control.Monad.IO.Class          (MonadIO)
import           Network.HTTP.Types              (status200)
import           Network.HTTP.Types.Header       (hContentType)
import           Network.Wai                     (responseLBS)
import           Network.Wai.Handler.Warp        (run)


import           Network.Wai.Middleware.HmacAuth


main :: IO ()
main = run 3000 $ authware app
  where
    -- apply auth middleware to an Application
    authware = hmacAuth lookupSecret defaultHmacAuthSettings

    -- use any io action you like (e.g. db lookup)
    -- see tests for another example of a lookup function
    lookupSecret :: MonadIO m => Key -> m (Maybe Secret)
    lookupSecret (Key _) = return $ Just $ Secret "secret"

    -- barebones wai app
    app _ f = f $ responseLBS
                         status200
                         [(hContentType, "text/plain")]
                         "Client Succesfully Authenticated."
