<script lang="ts">
    import { invoke } from "@tauri-apps/api/core";
    import { platform } from "@tauri-apps/plugin-os";
    import { relaunch } from "@tauri-apps/plugin-process";

    interface AppConfig {
        auto_connect: boolean;
    }

    let autoConnect = $state(false);
    let launchAtStartup = $state(false);
    let appVersion = $state("0.0.0");
    let updateStatus = $state<
        "idle" | "checking" | "available" | "downloading" | "ready" | "error"
    >("idle");
    let updateVersion = $state<string | null>(null);
    let updateProgress = $state(0);
    let isMobile = $state(false);
    let currentPlatform = $state("");

    $effect(() => {
        (async () => {
            try {
                // Detect platform
                currentPlatform = await platform();
                isMobile =
                    currentPlatform === "android" || currentPlatform === "ios";

                // Load config from backend
                const config: AppConfig = await invoke("get_config");
                autoConnect = config.auto_connect;

                // Get app version
                appVersion = await invoke("get_version");

                // Check autostart status (desktop only)
                if (!isMobile) {
                    const { isEnabled } = await import(
                        "@tauri-apps/plugin-autostart"
                    );
                    launchAtStartup = await isEnabled();
                }
            } catch (e) {
                console.error("Failed to load settings:", e);
            }
        })();
    });

    async function toggleAutostart() {
        if (isMobile) return;
        try {
            const { enable, disable } = await import(
                "@tauri-apps/plugin-autostart"
            );
            if (launchAtStartup) {
                await disable();
            } else {
                await enable();
            }
            launchAtStartup = !launchAtStartup;
        } catch (e) {
            console.error("Failed to toggle autostart:", e);
        }
    }

    async function saveSettings() {
        await invoke("set_config", {
            config: {
                auto_connect: autoConnect,
            },
        });
    }

    async function checkForUpdates() {
        if (isMobile) return;
        updateStatus = "checking";
        try {
            const { check } = await import("@tauri-apps/plugin-updater");
            const update = await check();
            if (update) {
                updateStatus = "available";
                updateVersion = update.version;
            } else {
                updateStatus = "idle";
            }
        } catch (e) {
            console.error("Update check failed:", e);
            updateStatus = "error";
        }
    }

    async function downloadAndInstall() {
        if (isMobile || updateStatus !== "available") return;
        updateStatus = "downloading";
        try {
            const { check } = await import("@tauri-apps/plugin-updater");
            const update = await check();
            if (update) {
                let totalLength = 0;
                let downloadedLength = 0;
                await update.downloadAndInstall((event: any) => {
                    if (event.event === "Started") {
                        totalLength = event.data.contentLength ?? 0;
                        downloadedLength = 0;
                        updateProgress = 0;
                    } else if (event.event === "Progress") {
                        downloadedLength += event.data.chunkLength;
                        if (totalLength > 0) {
                            updateProgress = Math.round(
                                (downloadedLength / totalLength) * 100,
                            );
                        }
                    } else if (event.event === "Finished") {
                        updateStatus = "ready";
                    }
                });
                updateStatus = "ready";
            }
        } catch (e) {
            console.error("Update download failed:", e);
            updateStatus = "error";
        }
    }

    async function restartApp() {
        await relaunch();
    }
</script>

<div class="settings">
    <div class="setting-group">
        <h3>General</h3>

        {#if !isMobile}
            <label class="setting-item">
                <div class="setting-info">
                    <span class="setting-name">Launch at startup</span>
                    <span class="setting-desc"
                        >Start Oxidize when you log in</span
                    >
                </div>
                <button
                    class="toggle"
                    class:active={launchAtStartup}
                    onclick={toggleAutostart}
                    aria-label="Toggle launch at startup"
                >
                    <span class="toggle-slider"></span>
                </button>
            </label>
        {/if}

        <label class="setting-item">
            <div class="setting-info">
                <span class="setting-name">Auto-connect</span>
                <span class="setting-desc">Connect automatically on launch</span
                >
            </div>
            <button
                class="toggle"
                class:active={autoConnect}
                onclick={() => {
                    autoConnect = !autoConnect;
                    saveSettings();
                }}
                aria-label="Toggle auto-connect"
            >
                <span class="toggle-slider"></span>
            </button>
        </label>
    </div>

    {#if !isMobile}
        <div class="setting-group">
            <h3>Updates</h3>
            <div class="setting-item">
                <div class="setting-info">
                    <span class="setting-name">App Version</span>
                    <span class="setting-desc">v{appVersion}</span>
                </div>
                {#if updateStatus === "idle"}
                    <button class="update-btn" onclick={checkForUpdates}>
                        Check for Updates
                    </button>
                {:else if updateStatus === "checking"}
                    <span class="update-status">Checking...</span>
                {:else if updateStatus === "available"}
                    <button
                        class="update-btn highlight"
                        onclick={downloadAndInstall}
                    >
                        Update to v{updateVersion}
                    </button>
                {:else if updateStatus === "downloading"}
                    <span class="update-status"
                        >Downloading... {updateProgress}%</span
                    >
                {:else if updateStatus === "ready"}
                    <button class="update-btn highlight" onclick={restartApp}>
                        Restart to Apply
                    </button>
                {:else if updateStatus === "error"}
                    <button class="update-btn" onclick={checkForUpdates}>
                        Retry
                    </button>
                {/if}
            </div>
        </div>
    {:else}
        <div class="setting-group">
            <h3>App Info</h3>
            <div class="setting-item">
                <div class="setting-info">
                    <span class="setting-name">Version</span>
                    <span class="setting-desc">v{appVersion}</span>
                </div>
                <span class="platform-badge">{currentPlatform}</span>
            </div>
        </div>
    {/if}

    <div class="about">
        <p class="links">
            <a href="https://github.com/gagansuie/oxidize" target="_blank"
                >GitHub</a
            >
            <span>•</span>
            <a href="https://oxd.sh" target="_blank">Website</a>
        </p>
    </div>
</div>

<style>
    .settings {
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }

    .setting-group h3 {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #666;
        margin-bottom: 0.75rem;
    }

    .setting-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.875rem 1rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        margin-bottom: 0.5rem;
        cursor: pointer;
    }

    .setting-item:hover {
        background: rgba(255, 255, 255, 0.05);
    }

    .setting-info {
        display: flex;
        flex-direction: column;
        gap: 0.125rem;
    }

    .setting-name {
        font-weight: 500;
        color: #e0e0e0;
        font-size: 0.9rem;
    }

    .setting-desc {
        font-size: 0.75rem;
        color: #666;
    }

    .toggle {
        width: 44px;
        height: 24px;
        border-radius: 12px;
        background: #2a2a4a;
        border: none;
        cursor: pointer;
        position: relative;
        transition: background 0.2s;
    }

    .toggle.active {
        background: #00d4aa;
    }

    .toggle-slider {
        position: absolute;
        top: 2px;
        left: 2px;
        width: 20px;
        height: 20px;
        border-radius: 50%;
        background: #fff;
        transition: transform 0.2s;
    }

    .toggle.active .toggle-slider {
        transform: translateX(20px);
    }

    .about {
        margin-top: 1rem;
        padding-top: 1rem;
        border-top: 1px solid #2a2a4a;
        text-align: center;
    }

    .about p {
        font-size: 0.8rem;
        color: #555;
        margin: 0.25rem 0;
    }

    .links {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
    }

    .links a {
        color: #00d4aa;
        text-decoration: none;
    }

    .links a:hover {
        text-decoration: underline;
    }

    .update-btn {
        padding: 0.5rem 1rem;
        border-radius: 8px;
        border: none;
        background: rgba(255, 255, 255, 0.1);
        color: #e0e0e0;
        font-size: 0.8rem;
        cursor: pointer;
        transition: all 0.2s;
    }

    .update-btn:hover {
        background: rgba(255, 255, 255, 0.15);
    }

    .update-btn.highlight {
        background: #00d4aa;
        color: #0f0f1a;
    }

    .update-btn.highlight:hover {
        background: #00b894;
    }

    .update-status {
        font-size: 0.8rem;
        color: #888;
    }

    .platform-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        background: rgba(0, 212, 170, 0.15);
        color: #00d4aa;
        font-size: 0.75rem;
        font-weight: 500;
        text-transform: capitalize;
    }
</style>
