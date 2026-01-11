<script lang="ts">
    import { invoke } from "@tauri-apps/api/core";
    import { enable, disable, isEnabled } from "@tauri-apps/plugin-autostart";

    interface AppConfig {
        auto_connect: boolean;
    }

    let autoConnect = $state(false);
    let launchAtStartup = $state(false);
    let appVersion = $state("0.0.0");

    $effect(() => {
        (async () => {
            try {
                // Load config from backend
                const config: AppConfig = await invoke("get_config");
                autoConnect = config.auto_connect;

                // Get app version
                appVersion = await invoke("get_version");

                // Check autostart status
                launchAtStartup = await isEnabled();
            } catch (e) {
                console.error("Failed to load settings:", e);
            }
        })();
    });

    async function toggleAutostart() {
        try {
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
</script>

<div class="settings">
    <div class="setting-group">
        <h3>General</h3>

        <label class="setting-item">
            <div class="setting-info">
                <span class="setting-name">Launch at startup</span>
                <span class="setting-desc">Start Oxidize when you log in</span>
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

    <div class="setting-group">
        <h3>Optimizations</h3>

        <div class="setting-item info-only">
            <div class="setting-info">
                <span class="setting-name">Smart Traffic Detection</span>
                <span class="setting-desc">Gaming & VoIP auto-prioritized</span>
            </div>
            <span class="status-badge">Active</span>
        </div>

        <div class="setting-item info-only">
            <div class="setting-info">
                <span class="setting-name">LZ4 Compression</span>
                <span class="setting-desc">Fast compression enabled</span>
            </div>
            <span class="status-badge">Active</span>
        </div>

        <div class="setting-item info-only">
            <div class="setting-info">
                <span class="setting-name">Split Tunneling</span>
                <span class="setting-desc">Streaming services bypassed</span>
            </div>
            <span class="status-badge">Active</span>
        </div>
    </div>

    <div class="about">
        <p>Oxidize v{appVersion}</p>
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

    .setting-item.info-only {
        cursor: default;
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

    .status-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        background: rgba(0, 212, 170, 0.15);
        color: #00d4aa;
        font-size: 0.75rem;
        font-weight: 500;
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
</style>
