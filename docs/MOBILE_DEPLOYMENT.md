# Mobile App Deployment

This guide covers deploying Oxidize to Google Play Store and Apple App Store, plus the smart network features available on mobile.

## Smart Network Features

Mobile clients include advanced network optimization that desktop apps can't match:

### HandoffPredictor - Seamless Network Transitions
Predicts WiFi→LTE transitions **5+ seconds ahead** using signal quality trends:

```rust
// Platform layer calls these when signal changes
mobile_client.update_wifi_signal(rssi, rtt_us);  // WiFi RSSI in dBm
mobile_client.update_cellular_signal(rsrp);       // LTE RSRP in dBm

// Check if handoff is predicted
if let Some(prediction) = mobile_client.check_handoff_prediction() {
    if prediction.should_enable_fec {
        // Proactive FEC before handoff occurs
        enable_high_fec_mode();
    }
    if prediction.should_prepare_backup {
        // Pre-establish LTE path
        prepare_backup_path();
    }
}
```

**Benefits:**
- Zero packet loss during network transitions
- Pre-established backup paths ready before handoff
- Proactive FEC when signal degrades

### MptcpRedundancyScheduler - Critical Packet Duplication
Duplicates time-sensitive packets on multiple network paths:

| Traffic Type | Importance | Behavior |
|--------------|------------|----------|
| Gaming/VoIP (STUN, RTP) | Critical | Always duplicate on both paths |
| QUIC, OxTunnel | High | Duplicate if path quality differs |
| SSH, HTTPS | Normal | Best path only |
| HTTP, FTP | Low | Can be delayed |

```rust
// Classify packet importance
let importance = mobile_client.classify_packet_importance(dst_port, protocol);

// Check if should send on backup path too
if mobile_client.should_send_redundant(importance, sequence) {
    send_on_backup_path(&packet);
}
```

**Industry Validation:** Apple FaceTime, Zoom, and cloud gaming services all use similar duplication for real-time traffic.

---

## App Store Deployment

## Prerequisites

### Google Play Store
1. Create a [Google Play Console](https://play.google.com/console) account ($25 one-time fee)
2. Create your app listing manually first
3. Create a Service Account for API access:
   - Go to Google Cloud Console → APIs & Services → Credentials
   - Create Service Account with "Service Account User" role
   - Download JSON key file
   - In Play Console, grant the service account access under Users & Permissions

### Apple App Store
1. Enroll in [Apple Developer Program](https://developer.apple.com/programs/) ($99/year)
2. Create your app in App Store Connect
3. Create an App Store Connect API Key:
   - Go to App Store Connect → Users and Access → Keys
   - Generate a new key with "App Manager" role
   - Download the .p8 file and note the Key ID and Issuer ID

## GitHub Secrets Required

### Android (Play Store)
| Secret | Description |
|--------|-------------|
| `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` | Contents of the service account JSON key file |

### iOS (App Store)
| Secret | Description |
|--------|-------------|
| `APP_STORE_CONNECT_KEY_ID` | API Key ID from App Store Connect |
| `APP_STORE_CONNECT_ISSUER_ID` | Issuer ID from App Store Connect |
| `APP_STORE_CONNECT_KEY_CONTENT` | Base64-encoded contents of the .p8 key file |
| `APPLE_TEAM_ID` | Your Apple Developer Team ID |
| `MATCH_PASSWORD` | Password for Match certificate encryption |
| `MATCH_GIT_URL` | Private repo URL for storing certificates |
| `MATCH_GIT_BASIC_AUTHORIZATION` | Base64-encoded `username:token` for git access |

## Setting Up Code Signing (iOS)

Fastlane Match manages iOS certificates and provisioning profiles in a private git repo.

```bash
# Initialize match (run locally once)
cd app
fastlane match init

# Generate certificates (run locally once)
fastlane match appstore
```

## Deployment

### Automatic (on release)
When you publish a GitHub release, the workflow automatically deploys to:
- Google Play Store (internal track)
- Apple TestFlight

### Manual deployment
Use the GitHub Actions workflow dispatch:

1. Go to Actions → "Deploy to App Stores"
2. Click "Run workflow"
3. Select platform (android/ios/both)
4. Select track (internal/beta/production)

## Release Tracks

### Android
- **internal**: Internal testing (immediate)
- **beta**: Closed/open testing
- **production**: Public release

### iOS
- **testflight**: TestFlight beta testing
- **production**: App Store release (requires review)

## Local Testing

```bash
# Android - validate credentials
cd app/src-tauri/gen/android
GOOGLE_PLAY_JSON_KEY_PATH=/path/to/key.json fastlane validate

# iOS - build locally
cd app
fastlane ios build
```

## Troubleshooting

### Android: "Package not found"
You must create the app listing in Play Console manually before first upload.

### iOS: "No matching provisioning profile"
Run `fastlane match appstore --force` to regenerate profiles.

### iOS: "App Store Connect API key invalid"
Ensure the .p8 key is base64-encoded: `base64 -i AuthKey_XXXXX.p8`
