{-# LANGUAGE DeriveGeneric #-}

module PolkitGuard.Types (
    Severity(..),
    Finding(..),
    Rule(..),
    ScanResult(..),
    Stats(..),
    RiskScore(..),
    emptyResult
) where

import GHC.Generics (Generic)
import Data.Aeson (FromJSON, ToJSON)

data Severity = SeverityLow | SeverityMedium | SeverityHigh | SeverityCritical
    deriving (Show, Eq, Generic)

instance FromJSON Severity where
    parseJSON (Number n) = case n of
        1 -> return SeverityLow
        2 -> return SeverityMedium
        3 -> return SeverityHigh
        4 -> return SeverityCritical
        _ -> return SeverityLow
    parseJSON _ = return SeverityLow

instance ToJSON Severity where
    toJSON s = toJSON $ case s of
        SeverityLow -> 1 :: Int
        SeverityMedium -> 2 :: Int
        SeverityHigh -> 3 :: Int
        SeverityCritical -> 4 :: Int

data Rule = Rule
    { action :: Maybe String
    , identity :: Maybe String
    , resultAny :: Maybe String
    , resultActive :: Maybe String
    , resultInactive :: Maybe String
    } deriving (Show, Eq, Generic)

instance FromJSON Rule
instance ToJSON Rule

data Finding = Finding
    { severity :: Severity
    , file :: Maybe String
    , ruleName :: Maybe String
    , ruleId :: Maybe String
    , title :: Maybe String
    , description :: Maybe String
    , message :: Maybe String
    , rule :: Maybe Rule
    } deriving (Show, Eq, Generic)

instance FromJSON Finding
instance ToJSON Finding

data Stats = Stats
    { filesScanned :: Int
    , rulesFound :: Int
    , critical :: Int
    , high :: Int
    , medium :: Int
    , low :: Int
    , total :: Int
    } deriving (Show, Eq, Generic)

data StatsStats = StatsStats Int Int Int Int Int Int Int
    deriving (Show, Eq)

instance FromJSON Stats where
    parseJSON = undefined
    {-parseJSON (Object v) = Stats
        <$> v .:? "files_scanned" .!= 0
        <*> v .:? "rules_found" .!= 0
        <*> v .:? "critical" .!= 0
        <*> v .:? "high" .!= 0
        <*> v .:? "medium" .!= 0
        <*> v .:? "low" .!= 0
        <*> v .:? "total" .!= 0
    parseJSON _ = fail "Expected Object"-}

data ScanResult = ScanResult
    { findings :: [Finding]
    , scanner :: String
    , stats :: Stats
    , version :: String
    } deriving (Show, Eq, Generic)

instance FromJSON ScanResult
instance ToJSON ScanResult

data RiskScore = RiskScore
    { overallScore :: Double
    , riskLevel :: String
    , criticality :: Double
    , likelihood :: Double
    , impactScore :: Double
    , recommendations :: [String]
    } deriving (Show, Eq, Generic)

instance FromJSON RiskScore
instance ToJSON RiskScore

emptyResult :: ScanResult
emptyResult = ScanResult [] "PolkitGuard" (Stats 0 0 0 0 0 0 0) "1.18.0"

-- | PolkitGuard Haskell package
-- License: MIT
-- 
-- Usage:
--
-- >>> import PolkitGuard
-- >>> result <- scan SeverityLow
-- >>> let risk = calculateRiskScore $ findings result
-- >>> print $ riskLevel risk