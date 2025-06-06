<script lang="ts">
  import { auth } from "$lib/stores/auth.store";
  import ClientCard from "$lib/components/ClientCard.svelte";
  import * as Pagination from "$lib/components/ui/pagination/index.js";
  import { Badge } from "$lib/components/ui/badge";
  import type { Client, PageServerData, UserGroup } from "$lib/types";
  import { onMount } from "svelte";
  import { Users, Search, LayoutDashboard, Zap } from "@lucide/svelte";
  import HeroHeader from "$lib/components/hero-header.svelte";

  interface Props {
    data: PageServerData;
  }

  let { data }: Props = $props();

  // All data now comes from server
  let userGroups: UserGroup[] = data.userGroups || [];
  const accessibleClients: Client[] = data.clients?.data || [];
  const error = data.status === "error" ? data.error : null;

  // Pagination state
  let itemsPerPage = 6; // 3 rows of 3 cards in desktop view

  // Calculate total items
  let totalItems = $derived(accessibleClients.length);

  // Get current page items based on pagination component's current page
  function getPaginatedClients(currentPage: number) {
    return accessibleClients.slice(
      (currentPage - 1) * itemsPerPage,
      currentPage * itemsPerPage
    );
  }

  // Default to 3 columns, but we'll update this based on screen size
  let gridColumns = $state(3);
  let searchTerm = $state("");

  onMount(() => {
    // Update columns based on screen size
    updateGridColumns();

    // Listen for window resize to update columns
    window.addEventListener("resize", updateGridColumns);

    // Apply fade-in animation to the header
    const header = document.querySelector(".dashboard-header");
    if (header) {
      header.classList.add("animate-fade-in");
    }

    return () => {
      window.removeEventListener("resize", updateGridColumns);
    };
  });

  function updateGridColumns() {
    // Determine number of columns based on screen width
    if (window.innerWidth >= 1280) {
      gridColumns = 4; // xl screens
    } else if (window.innerWidth >= 1024) {
      gridColumns = 3; // lg screens
    } else if (window.innerWidth >= 768) {
      gridColumns = 2; // md screens
    } else {
      gridColumns = 1; // sm screens
    }
  }
</script>

<svelte:head>
  <title>Dashboard - Pocket ID Portal</title>
</svelte:head>

<!-- Modern Dashboard Layout -->
<div class="space-y-8 max-w-[1200px] mx-auto flex flex-col h-full">
  <!-- Hero Header Section with Gradient Background -->
  <HeroHeader
    title="My Applications"
    description="Access all your authorized applications from this portal."
    icon={LayoutDashboard}
  >
    {#snippet actions()}
      <div class="relative w-full md:w-auto">
        <div
          class="flex items-center h-10 w-full md:w-[300px] rounded-xl border bg-background px-3 focus-within:ring-1 focus-within:ring-primary"
        >
          <Search class="size-4 text-muted-foreground mr-2" />
          <input
            type="text"
            placeholder="Search applications..."
            class="flex-1 bg-transparent outline-none text-sm"
            bind:value={searchTerm}
          />
        </div>
      </div>
    {/snippet}
  </HeroHeader>

  {#if error}
    <div class="rounded-xl border bg-destructive/5 p-6 animate-fade-in">
      <div class="flex items-center gap-3">
        <div class="p-2 bg-destructive/10 rounded-full">
          <Zap class="size-5 text-destructive" />
        </div>
        <div>
          <h3 class="text-lg font-medium text-destructive">
            Error loading applications
          </h3>
          <p class="text-sm text-muted-foreground mt-1">{error}</p>
        </div>
      </div>
      <div class="mt-4 flex justify-end">
        <button
          class="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          onclick={() => window.location.reload()}
        >
          Try Again
        </button>
      </div>
    </div>
  {:else}
    <div class="flex flex-col md:flex-row gap-6">
      <!-- Groups Panel -->
      <div class="w-full md:w-1/4">
        <div
          class="rounded-xl border bg-card shadow-sm p-5 sticky top-6 h-[calc(100vh-16rem)] flex flex-col animate-fade-in"
          style="animation-delay: 100ms;"
        >
          <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-2">
              <div class="bg-primary/10 p-1.5 rounded-md">
                <Users class="size-4 text-primary" />
              </div>
              <h3 class="font-medium">Your Access Groups</h3>
            </div>
            <div
              class="bg-muted text-xs font-semibold rounded-full px-2 py-0.5"
            >
              {userGroups.length}
            </div>
          </div>

          {#if userGroups.length > 0}
            <div class="grow space-y-2 overflow-y-auto pr-1 custom-scrollbar">
              {#each userGroups as group, i (group.id)}
                <div
                  class="group flex items-center gap-2 p-2 rounded-lg hover:bg-muted/50 transition-colors animate-fade-in opacity-0"
                  style="animation-delay: {150 + i * 75}ms"
                >
                  <Badge
                    variant="outline"
                    class="w-full justify-between py-1.5 px-3 text-xs group-hover:border-primary/50"
                  >
                    <span class="truncate">{group.name}</span>
                    <div class="size-2 rounded-full bg-primary/70"></div>
                  </Badge>
                </div>
              {/each}
            </div>
          {:else}
            <div
              class="grow text-muted-foreground text-sm flex items-center justify-center gap-2 p-3 border border-dashed rounded-lg bg-muted/5"
            >
              <Users class="size-4" />
              <span>No groups assigned</span>
            </div>
          {/if}
        </div>
      </div>

      <!-- Main Content - Applications Grid -->
      <div class="w-full md:w-3/4 flex flex-col h-[calc(100vh-16rem)]">
        <Pagination.Root count={totalItems} perPage={itemsPerPage}>
          {#snippet children({ pages, currentPage })}
            <div
              class="rounded-xl border bg-card shadow-sm grow flex flex-col w-full overflow-hidden h-full animate-fade-in"
              style="animation-delay: 150ms;"
            >
              <div class="p-5 border-b">
                <div class="flex items-center justify-between">
                  <h3 class="text-lg font-medium flex items-center gap-2">
                    <Zap class="size-5 text-primary" />
                    Applications
                  </h3>
                  <div class="flex items-center gap-2">
                    <Badge variant="outline" class="bg-muted/30">
                      {accessibleClients.length} apps
                    </Badge>
                    {#if Math.ceil(totalItems / itemsPerPage) > 1}
                      <div class="ml-4">
                        <Pagination.Content>
                          <Pagination.Item>
                            <Pagination.PrevButton />
                          </Pagination.Item>
                          {#each pages as page (page.key)}
                            {#if page.type === "ellipsis"}
                              <Pagination.Item>
                                <Pagination.Ellipsis />
                              </Pagination.Item>
                            {:else}
                              <Pagination.Item>
                                <Pagination.Link
                                  {page}
                                  isActive={currentPage === page.value}
                                >
                                  {page.value}
                                </Pagination.Link>
                              </Pagination.Item>
                            {/if}
                          {/each}
                          <Pagination.Item>
                            <Pagination.NextButton />
                          </Pagination.Item>
                        </Pagination.Content>
                      </div>
                    {/if}
                  </div>
                </div>
              </div>

              <div class="grow overflow-auto p-5 pt-3">
                {#if accessibleClients.length === 0}
                  <div
                    class="flex flex-col items-center justify-center py-12 text-center bg-muted/5 rounded-lg border-dashed border-2 my-4 mx-2"
                  >
                    <div class="rounded-full bg-muted/30 p-4 mb-4">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="24"
                        height="24"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        class="text-muted-foreground"
                      >
                        <rect width="8" height="8" x="2" y="2" rx="1"></rect>
                        <path d="M6 6h.01"></path>
                        <rect width="8" height="8" x="14" y="2" rx="1"></rect>
                        <path d="M18 6h.01"></path>
                        <rect width="8" height="8" x="2" y="14" rx="1"></rect>
                        <path d="M6 18h.01"></path>
                        <rect width="8" height="8" x="14" y="14" rx="1"></rect>
                        <path d="M18 18h.01"></path>
                      </svg>
                    </div>
                    <h3 class="text-lg font-medium">No applications found</h3>
                    <p
                      class="text-sm text-muted-foreground mt-1 max-w-sm mx-auto"
                    >
                      You don't have access to any applications yet. Contact
                      your administrator to request access.
                    </p>
                  </div>
                {:else}
                  <div
                    class="grid gap-4 grid-cols-1 sm:grid-cols-2 md:grid-cols-3 w-full h-full"
                  >
                    {#each getPaginatedClients(currentPage).filter((client) => searchTerm.trim() === "" || client.name
                          .toLowerCase()
                          .includes(searchTerm.toLowerCase()) || client.description
                          ?.toLowerCase()
                          .includes(searchTerm.toLowerCase())) as client, i}
                      <div
                        class="min-h-[200px] animate-fade-in opacity-0"
                        style="animation-delay: {200 + i * 75}ms"
                      >
                        <ClientCard {client} index={i} columns={gridColumns} />
                      </div>
                    {/each}
                  </div>
                {/if}
              </div>
            </div>
          {/snippet}
        </Pagination.Root>
      </div>
    </div>
  {/if}
</div>
