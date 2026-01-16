# Mobile App Store Deployment

This guide covers deploying Oxidize to Google Play Store and Apple App Store using Fastlane.

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
