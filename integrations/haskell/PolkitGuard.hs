-- Haskell bindings for PolkitGuard

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module PolkitGuard (
    module PolkitGuard.Types,
    scan,
    scanPath,
    calculateRiskScore,
    version,
    healthy,
    main
) where

import PolkitGuard.Types
import GHC.Generics (Generic)
import Data.Aeson (FromJSON, ToJSON, decode, encode)
import qualified Data.Text as T
import System.Process (readProcessWithExitCode)
import Control.Exception (try, SomeException)

version :: String
version = "1.18.0"

scan :: Severity -> IO ScanResult
scan severity = scanPath Nothing severity

scanPath :: Maybe FilePath -> Severity -> IO ScanResult
scanPath path severity = do
    let args = ["--format", "json", "--severity", show severity]
            ++ maybe [] (\p -> ["--path", p]) path
        polkitCmd = "polkitguard"
    (exitCode, stdout, stderr) <- readProcessWithExitCode polkitCmd args ""
    case exitCode of
        ExitSuccess -> case decode (T.pack stdout) of
            Just result -> return result
            Nothing -> return $ emptyResult { scanner = "PolkitGuard", version = version }
        ExitFailure _ -> return $ emptyResult { scanner = "PolkitGuard", version = version }

calculateRiskScore :: [Finding] -> RiskScore
calculateRiskScore findings = RiskScore
    { overallScore = score
    , riskLevel = level
    , criticality = critical / total * 10
    , likelihood = high / total * 10
    , impactScore = (critical + high) / total * 10
    , recommendations = recs
    }
  where
    total = max (length findings) 1
    critical = length $ filter (\f -> severity f == SeverityCritical) findings
    high = length $ filter (\f -> severity f == SeverityHigh) findings
    medium = length $ filter (\f -> severity f == SeverityMedium) findings
    low = length $ filter (\f -> severity f == SeverityLow) findings
    score = (fromIntegral $ critical * 10 + high * 7 + medium * 4 + low * 1) / fromIntegral total
    level = case score of
        s | s >= 8 -> "CRITICAL"
          | s >= 6 -> "HIGH"
          | s >= 4 -> "MEDIUM"
          | s >= 2 -> "LOW"
          | otherwise -> "MINIMAL"
    recs = []
        ++ (if critical > 0 then ["URGENT: Critical issues found"] else [])
        ++ (if high > 0 then ["High priority: Review within 24 hours"] else [])
        ++ (if medium > 0 then ["Medium priority: Schedule remediation"] else [])

healthy :: IO Bool
healthy = do
    result <- scan SeverityCritical
    return $ null $ findings result

emptyResult :: ScanResult
emptyResult = ScanResult
    { findings = []
    , scanner = "PolkitGuard"
    , stats = StatsStats 0 0 0 0 0 0 0
    , version = version
    }

main :: IO ()
main = do
    result <- scan SeverityLow
    putStrLn $ "PolkitGuard v" ++ version
    putStrLn $ "Found " ++ show (length $ findings result) ++ " findings"
    let risk = calculateRiskScore $ findings result
    putStrLn $ "Risk Score: " ++ show (overallScore risk) ++ " (" ++ riskLevel risk ++ ")"