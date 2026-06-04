# Sample Incident Report

## Summary
DangerScope detected multiple suspicious events from 192.168.1.10, including repeated failed login attempts against /login.

## Detection
The IP triggered the Possible Brute Force rule after 5 failed login attempts.

## Impact
The activity may indicate an attempted account takeover.

## Recommendation
Review authentication logs, temporarily rate-limit the source IP, and verify whether any successful login followed the failed attempts.

## Limitations
This alert is based on request patterns and does not confirm a successful compromise.