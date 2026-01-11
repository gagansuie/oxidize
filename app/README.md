# Oxidize App

Cross-platform GUI for Oxidize VPN built with Tauri 2.0.

## Supported Platforms

| Platform | Status |
|----------|--------|
| Windows  | ✅ |
| macOS    | ✅ |
| Linux    | ✅ |
| Android  | ✅ (Tauri 2.0) |
| iOS      | ✅ (Tauri 2.0) |

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18
- [Rust](https://rustup.rs/) >= 1.70
- Platform-specific dependencies:
  - **Linux**: `sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev`
  - **macOS**: Xcode Command Line Tools
  - **Windows**: WebView2, Visual Studio Build Tools

## Development

```bash
# Install dependencies
cd app
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

## Project Structure

```
app/
├── src/                    # Svelte frontend
│   ├── lib/               # Components
│   │   ├── ServerList.svelte
│   │   ├── Settings.svelte
│   │   └── Stats.svelte
│   ├── App.svelte         # Main app component
│   └── main.ts            # Entry point
├── src-tauri/             # Rust backend
│   ├── src/
│   │   ├── lib.rs         # Tauri setup + tray
│   │   ├── main.rs        # Entry point
│   │   └── commands.rs    # IPC commands
│   ├── capabilities/      # Tauri permissions
│   ├── icons/             # App icons
│   ├── Cargo.toml
│   └── tauri.conf.json
├── package.json
└── vite.config.ts
```

## Features

- **System Tray**: Quick connect/disconnect from tray icon
- **Server Selection**: Browse and select VPN servers
- **Connection Stats**: Real-time bandwidth and uptime
- **Settings**: Kill switch, DNS leak protection, auto-start
- **Cross-platform**: Native look and feel on all platforms

## Building for Mobile

### Android

```bash
npm run tauri android init
npm run tauri android dev
npm run tauri android build
```

### iOS

```bash
npm run tauri ios init
npm run tauri ios dev
npm run tauri ios build
```

## Icons

Generate app icons from a 1024x1024 PNG:

```bash
npm run tauri icon /path/to/icon.png
```
