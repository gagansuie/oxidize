<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import ServerList from "./lib/ServerList.svelte";
  import Settings from "./lib/Settings.svelte";
  import Stats from "./lib/Stats.svelte";
  import Analytics from "./lib/Analytics.svelte";
  import type { ConnectionStatus, AppConfig } from "./lib/types";

  interface Region {
    id: string;
    name: string;
    location: string;
    country_code: string;
    status: string;
    latency_ms: number | null;
    load: number;
    server_count: number;
    server_ids: string[];
  }

  let status: ConnectionStatus = $state({
    connected: false,
    server: null,
    ip: null,
    original_ip: null,
    uptime_secs: 0,
    bytes_sent: 0,
    bytes_received: 0,
    packets_sent: 0,
    packets_received: 0,
    compression_saved: 0,
    latency_ms: null,
    direct_latency_ms: null,
    fec_recovered: 0,
    fec_sent: 0,
    loss_predictions: 0,
    congestion_adjustments: 0,
    path_switches: 0,
  });

  let connecting = $state(false);
  let activeTab = $state<"servers" | "stats" | "settings">("servers");
  let selectedRegionId = $state<string | null>(null);
  let selectedServerId = $state<string | null>(null);
  let selectedRegionLocation = $state<string | null>(null);
  let connectedRegionLocation = $state<string | null>(null);
  let autoConnectAttempted = $state(false);
  let errorMessage = $state<string | null>(null);
  let initializing = $state(true);
  let initError = $state<string | null>(null);

  async function autoConnect() {
    if (autoConnectAttempted || connecting || status.connected) return;
    autoConnectAttempted = true;

    try {
      const config: AppConfig = await invoke("get_config");
      if (!config.auto_connect) return;

      console.log("Auto-connect enabled, finding closest region...");
      const closestRegion: Region = await invoke("get_closest_region");

      if (closestRegion && closestRegion.server_ids.length > 0) {
        const serverId = closestRegion.server_ids[0];
        console.log(
          `Auto-connecting to ${closestRegion.location} (${serverId})`,
        );

        selectedRegionId = closestRegion.id;
        selectedServerId = serverId;
        selectedRegionLocation = closestRegion.location;

        connecting = true;
        status = await invoke("connect", { serverId });
        connectedRegionLocation = closestRegion.location;
      }
    } catch (e) {
      console.error("Auto-connect failed:", e);
    } finally {
      connecting = false;
    }
  }

  async function syncSelectionWithConnection(regions: Region[]) {
    if (!status.connected || !status.server) return;

    const connectedServerId = status.server;
    const region = regions.find((r) =>
      r.server_ids.includes(connectedServerId),
    );

    if (region) {
      selectedRegionId = region.id;
      selectedServerId = connectedServerId;
      selectedRegionLocation = region.location;
      connectedRegionLocation = region.location;
    }
  }

  $effect(() => {
    let unlisten: UnlistenFn | undefined;
    let pollInterval: ReturnType<typeof setInterval> | undefined;
    let retryTimeout: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;

    async function initialize(retryCount = 0) {
      if (cancelled) return;

      try {
        initializing = true;
        initError = null;

        status = await invoke("get_status");

        // If already connected on startup, sync selection
        if (status.connected && status.server) {
          try {
            const regions: Region[] = await invoke("get_regions");
            await syncSelectionWithConnection(regions);
          } catch (e) {
            console.error("Failed to sync selection:", e);
          }
        } else {
          // Try auto-connect if not already connected
          await autoConnect();
        }

        unlisten = await listen("connection-changed", (event) => {
          status.connected = event.payload as boolean;
        });

        // Poll for status updates
        pollInterval = setInterval(async () => {
          try {
            status = await invoke("get_status");
          } catch (e) {
            console.error("Status poll failed:", e);
          }
        }, 1000);

        initializing = false;
      } catch (e) {
        console.error(`Initialization failed (attempt ${retryCount + 1}):`, e);

        if (cancelled) return;

        // Retry with exponential backoff (max 5 seconds)
        const delay = Math.min(1000 * Math.pow(1.5, retryCount), 5000);
        initError = `Connecting to service... (retry in ${Math.round(delay / 1000)}s)`;

        retryTimeout = setTimeout(() => initialize(retryCount + 1), delay);
      }
    }

    initialize();

    return () => {
      cancelled = true;
      unlisten?.();
      if (pollInterval) clearInterval(pollInterval);
      if (retryTimeout) clearTimeout(retryTimeout);
    };
  });

  async function toggleConnection() {
    if (connecting) return;
    connecting = true;
    errorMessage = null;

    try {
      if (status.connected) {
        status = await invoke("disconnect");
        connectedRegionLocation = null;
      } else {
        // Use selected server (best server from selected region)
        if (!selectedServerId) {
          errorMessage = "Please select a server first";
          return;
        }
        status = await invoke("connect", { serverId: selectedServerId });
        // Store the region location for display
        connectedRegionLocation = selectedRegionLocation;
      }
    } catch (e) {
      console.error("Connection error:", e);
      errorMessage =
        typeof e === "string" ? e : (e as Error).message || "Connection failed";
    } finally {
      connecting = false;
    }
  }

  function handleRegionSelect(
    regionId: string,
    serverId: string,
    regionLocation: string,
  ) {
    selectedRegionId = regionId;
    selectedServerId = serverId;
    selectedRegionLocation = regionLocation;
  }
</script>

{#if initializing}
  <main class="app initializing">
    <div class="init-screen">
      <div class="logo">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        <span>Oxidize</span>
      </div>
      <div class="init-spinner"></div>
      {#if initError}
        <p class="init-message">{initError}</p>
      {:else}
        <p class="init-message">Starting up...</p>
      {/if}
    </div>
  </main>
{:else}
  <main class="app">
    <header class="header">
      <div class="logo">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        <span>Oxidize</span>
      </div>
      <div class="status-badge" class:connected={status.connected}>
        <span class="dot"></span>
        {status.connected ? "Connected" : "Disconnected"}
      </div>
    </header>

    <section class="connection-panel">
      <button
        class="connect-btn"
        class:connected={status.connected}
        class:connecting
        disabled={connecting || (!status.connected && !selectedServerId)}
        onclick={toggleConnection}
      >
        <div class="btn-inner">
          {#if connecting}
            <div class="spinner"></div>
          {:else if status.connected}
            <svg viewBox="0 0 24 24" fill="currentColor">
              <path d="M6 4h4v16H6zM14 4h4v16h-4z" />
            </svg>
          {:else}
            <svg viewBox="0 0 24 24" fill="currentColor">
              <path d="M8 5v14l11-7z" />
            </svg>
          {/if}
        </div>
      </button>

      <div class="connection-info">
        {#if errorMessage}
          <p class="error">{errorMessage}</p>
        {:else if status.connected}
          {#if status.ip}
            <p class="ip">
              Protected IP: <strong>{status.ip}</strong>
            </p>
          {/if}
          <p class="server">
            Connected to: <strong
              >{connectedRegionLocation ||
                selectedRegionLocation ||
                "Unknown"}</strong
            >
          </p>
        {:else if selectedRegionLocation}
          <p class="ready">
            Ready to connect to <strong>{selectedRegionLocation}</strong>
          </p>
        {:else}
          <p class="select-prompt">Select a region to connect</p>
        {/if}
      </div>
    </section>

    {#if status.connected}
      <Stats {status} />
    {/if}

    <nav class="tabs">
      <button
        class:active={activeTab === "servers"}
        onclick={() => (activeTab = "servers")}
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <circle cx="12" cy="12" r="10" />
          <path
            d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"
          />
        </svg>
        Servers
      </button>
      <button
        class:active={activeTab === "stats"}
        onclick={() => (activeTab = "stats")}
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <path d="M18 20V10M12 20V4M6 20v-6" />
        </svg>
        Stats
      </button>
      <button
        class:active={activeTab === "settings"}
        onclick={() => (activeTab = "settings")}
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <path
            d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"
          />
          <circle cx="12" cy="12" r="3" />
        </svg>
        Settings
      </button>
    </nav>

    <section class="content">
      {#if activeTab === "servers"}
        <ServerList onselect={handleRegionSelect} selected={selectedRegionId} />
      {:else if activeTab === "stats"}
        <Analytics {status} />
      {:else}
        <Settings />
      {/if}
    </section>
  </main>
{/if}

<style>
  .initializing {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .init-screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1.5rem;
    text-align: center;
  }

  .init-screen .logo {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 2rem;
    font-weight: 700;
    color: #00d4aa;
  }

  .init-screen .logo svg {
    width: 36px;
    height: 36px;
  }

  .init-spinner {
    width: 40px;
    height: 40px;
    border: 3px solid #2a2a4a;
    border-top-color: #00d4aa;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .init-message {
    color: #888;
    font-size: 0.9rem;
  }
  :global(*) {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen,
      Ubuntu, sans-serif;
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 100%);
    color: #e0e0e0;
    min-height: 100vh;
  }

  .app {
    max-width: 400px;
    margin: 0 auto;
    padding: 1.5rem;
    min-height: 100vh;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 1.5rem;
    font-weight: 700;
    color: #00d4aa;
  }

  .logo svg {
    width: 28px;
    height: 28px;
  }

  .status-badge {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    background: rgba(255, 100, 100, 0.15);
    color: #ff6b6b;
    font-size: 0.85rem;
    font-weight: 500;
  }

  .status-badge.connected {
    background: rgba(0, 212, 170, 0.15);
    color: #00d4aa;
  }

  .status-badge .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
  }

  .connection-panel {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem 0;
  }

  .connect-btn {
    width: 140px;
    height: 140px;
    border-radius: 50%;
    border: 4px solid #2a2a4a;
    background: linear-gradient(145deg, #1e1e36, #252545);
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .connect-btn:hover:not(:disabled) {
    border-color: #00d4aa;
    box-shadow: 0 0 30px rgba(0, 212, 170, 0.3);
  }

  .connect-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .connect-btn.connected {
    border-color: #00d4aa;
    box-shadow: 0 0 40px rgba(0, 212, 170, 0.4);
  }

  .btn-inner {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    background: linear-gradient(145deg, #252545, #1e1e36);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .connect-btn.connected .btn-inner {
    background: linear-gradient(145deg, #00d4aa, #00b894);
  }

  .btn-inner svg {
    width: 40px;
    height: 40px;
    color: #00d4aa;
  }

  .connect-btn.connected .btn-inner svg {
    color: #0f0f1a;
  }

  .spinner {
    width: 30px;
    height: 30px;
    border: 3px solid #2a2a4a;
    border-top-color: #00d4aa;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .connection-info {
    margin-top: 1.5rem;
    text-align: center;
  }

  .connection-info p {
    font-size: 0.9rem;
    color: #888;
    margin: 0.25rem 0;
  }

  .connection-info strong {
    color: #00d4aa;
  }

  .connection-info .error {
    color: #ff6b6b;
    background: rgba(255, 100, 100, 0.1);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-size: 0.85rem;
  }

  .tabs {
    display: flex;
    gap: 0.5rem;
    margin: 1.5rem 0 1rem;
    border-bottom: 1px solid #2a2a4a;
    padding-bottom: 0.5rem;
  }

  .tabs button {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem;
    background: transparent;
    border: none;
    color: #666;
    font-size: 0.9rem;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s;
  }

  .tabs button:hover {
    color: #888;
    background: rgba(255, 255, 255, 0.05);
  }

  .tabs button.active {
    color: #00d4aa;
    background: rgba(0, 212, 170, 0.1);
  }

  .tabs button svg {
    width: 18px;
    height: 18px;
  }

  .content {
    flex: 1;
  }
</style>
