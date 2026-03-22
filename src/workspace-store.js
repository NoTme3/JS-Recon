// src/workspace-store.js — IndexedDB-backed workspace & analysis persistence
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  const DB_NAME = 'jsa-workspaces';
  const DB_VERSION = 1;

  /** Open (or create) the database */
  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('workspaces')) {
          const ws = db.createObjectStore('workspaces', { keyPath: 'id' });
          ws.createIndex('updatedAt', 'updatedAt', { unique: false });
        }
        if (!db.objectStoreNames.contains('analyses')) {
          const an = db.createObjectStore('analyses', { keyPath: 'id' });
          an.createIndex('workspaceId', 'workspaceId', { unique: false });
          an.createIndex('analyzedAt', 'analyzedAt', { unique: false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  /** Generic transaction helper */
  function txn(storeName, mode, fn) {
    return openDB().then(db => new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, mode);
      const store = tx.objectStore(storeName);
      const result = fn(store);
      tx.oncomplete = () => resolve(result._deferred || result);
      tx.onerror = () => reject(tx.error);
    }));
  }

  /** Get-all helper with deferred result capture */
  function getAllFromStore(storeName, indexName, query) {
    return openDB().then(db => new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const target = indexName ? store.index(indexName) : store;
      const req = query !== undefined ? target.getAll(query) : target.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }));
  }

  /** Get single record helper */
  function getFromStore(storeName, key) {
    return openDB().then(db => new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }));
  }

  /** Put record helper */
  function putToStore(storeName, record) {
    return openDB().then(db => new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      store.put(record);
      tx.oncomplete = () => resolve(record);
      tx.onerror = () => reject(tx.error);
    }));
  }

  /** Delete record helper */
  function deleteFromStore(storeName, key) {
    return openDB().then(db => new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    }));
  }

  // ─── Generate unique ID ───
  function uid() {
    return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  }

  // ═══════════════════════════════════════════════════════
  // PUBLIC API — JSA.WorkspaceStore
  // ═══════════════════════════════════════════════════════

  JSA.WorkspaceStore = {

    /** Create a new workspace */
    async createWorkspace(name) {
      const workspace = {
        id: uid(),
        name: name.trim(),
        createdAt: Date.now(),
        updatedAt: Date.now()
      };
      await putToStore('workspaces', workspace);
      return workspace;
    },

    /** List all workspaces sorted by updatedAt (newest first) */
    async listWorkspaces() {
      const all = await getAllFromStore('workspaces');
      return all.sort((a, b) => b.updatedAt - a.updatedAt);
    },

    /** Rename a workspace */
    async renameWorkspace(id, name) {
      const ws = await getFromStore('workspaces', id);
      if (!ws) throw new Error('Workspace not found');
      ws.name = name.trim();
      ws.updatedAt = Date.now();
      await putToStore('workspaces', ws);
      return ws;
    },

    /** Delete a workspace and ALL its analyses */
    async deleteWorkspace(id) {
      // Delete all analyses belonging to this workspace
      const analyses = await getAllFromStore('analyses', 'workspaceId', id);
      const db = await openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(['workspaces', 'analyses'], 'readwrite');
        const wsStore = tx.objectStore('workspaces');
        const anStore = tx.objectStore('analyses');
        wsStore.delete(id);
        analyses.forEach(a => anStore.delete(a.id));
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    },

    /** Save a new analysis under a workspace */
    async saveAnalysis(workspaceId, fileName, results, code) {
      const analysis = {
        id: uid(),
        workspaceId,
        fileName,
        results,
        code,
        analyzedAt: Date.now(),
        // Store a lightweight summary for sidebar display
        summary: {}
      };
      // Build count summary per category
      if (results) {
        for (const [cat, items] of Object.entries(results)) {
          if (Array.isArray(items)) analysis.summary[cat] = items.length;
        }
      }
      analysis.totalFindings = Object.values(analysis.summary).reduce((s, n) => s + n, 0);

      await putToStore('analyses', analysis);

      // Touch workspace updatedAt
      try {
        const ws = await getFromStore('workspaces', workspaceId);
        if (ws) {
          ws.updatedAt = Date.now();
          await putToStore('workspaces', ws);
        }
      } catch (e) { /* ignore */ }

      return analysis;
    },

    /** List all analyses for a workspace (newest first) */
    async listAnalyses(workspaceId) {
      const all = await getAllFromStore('analyses', 'workspaceId', workspaceId);
      return all.sort((a, b) => b.analyzedAt - a.analyzedAt);
    },

    /** Get a single analysis by ID */
    async getAnalysis(id) {
      return getFromStore('analyses', id);
    },

    /** Rename an analysis */
    async renameAnalysis(id, newName) {
      const an = await getFromStore('analyses', id);
      if (!an) throw new Error('Analysis not found');
      an.fileName = newName.trim();
      await putToStore('analyses', an);
      return an;
    },

    /** Delete a single analysis */
    async deleteAnalysis(id) {
      return deleteFromStore('analyses', id);
    }
  };

})();
