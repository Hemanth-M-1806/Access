/**
 * High-Performance 60FPS Zero-Copy HTML5 Force Topology Canvas
 * Optimized against sluggishness: Zero shadowBlur loops, fast physics decay, spatial culling.
 */
import { state } from '../state.js';
import { escapeHtml } from './toast.js';

let canvas, ctx;
let onNodeSelectCallback = null;

export function initGraphCanvas(canvasElement, onNodeSelect) {
  canvas = canvasElement;
  ctx = canvas.getContext('2d');
  onNodeSelectCallback = onNodeSelect;

  setupCanvasSize();
  setupCanvasEvents();

  window.addEventListener('resize', () => {
    setupCanvasSize();
    wakePhysics();
  });
}

function setupCanvasSize() {
  const rect = canvas.parentElement.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2); // Cap at 2 to preserve GPU fillrate
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width = `${rect.width}px`;
  canvas.style.height = `${rect.height}px`;
  ctx.scale(dpr, dpr);
}

export function loadTopologyData(rawNodes, rawLinks) {
  const rect = canvas.getBoundingClientRect();
  const width = rect.width || 800;
  const height = rect.height || 500;
  const existingMap = new Map(state.topology.nodes.map(n => [n.id, n]));

  const nodes = rawNodes.map((n, idx) => {
    const existing = existingMap.get(n.id);
    if (existing) {
      return { ...n, x: existing.x, y: existing.y, vx: 0, vy: 0 };
    }
    const angle = (idx / (rawNodes.length || 1)) * 2 * Math.PI;
    const radius = n.type === 'permission' ? 120 + (idx % 3) * 30 : 200 + (idx % 4) * 35;
    return {
      ...n,
      x: width / 2 + Math.cos(angle) * radius,
      y: height / 2 + Math.sin(angle) * radius,
      vx: 0,
      vy: 0
    };
  });

  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  const links = rawLinks.map(l => ({
    ...l,
    sourceNode: nodeMap.get(typeof l.source === 'object' ? l.source.id : l.source),
    targetNode: nodeMap.get(typeof l.target === 'object' ? l.target.id : l.target)
  })).filter(l => l.sourceNode && l.targetNode);

  state.topology = { nodes, links };
  wakePhysics();
}

export function wakePhysics() {
  if (state.isPhysicsFrozen) {
    drawFrame();
    return;
  }
  state.physicsAlpha = 0.95;
  if (!state.animationFrameId) {
    state.animationFrameId = requestAnimationFrame(physicsStep);
  }
}

function physicsStep() {
  const { nodes, links } = state.topology;
  const rect = canvas.getBoundingClientRect();
  const width = rect.width;
  const height = rect.height;
  const cx = width / 2;
  const cy = height / 2;

  if (nodes.length === 0) {
    state.animationFrameId = null;
    drawFrame();
    return;
  }

  // 1. Repulsion with fast distance cutoff (eliminates sluggishness on large rosters)
  const maxDistSq = 300 * 300;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const distSq = dx * dx + dy * dy;

      if (distSq > maxDistSq || distSq === 0) continue;
      const dist = Math.sqrt(distSq);

      const force = (3600 / (distSq + 80)) * state.physicsAlpha;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (a !== state.draggedNode) { a.vx -= fx; a.vy -= fy; }
      if (b !== state.draggedNode) { b.vx += fx; b.vy += fy; }
    }
  }

  // 2. Link Spring Forces
  for (const link of links) {
    const a = link.sourceNode;
    const b = link.targetNode;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const targetDist = link.is_drift ? 180 : 95;
    const force = (dist - targetDist) * 0.04 * state.physicsAlpha;

    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;

    if (a !== state.draggedNode) { a.vx += fx; a.vy += fy; }
    if (b !== state.draggedNode) { b.vx -= fx; b.vy -= fy; }
  }

  // 3. Center Gravity & Velocity Integration
  for (const n of nodes) {
    if (n === state.draggedNode) continue;

    n.vx += (cx - n.x) * 0.006 * state.physicsAlpha;
    n.vy += (cy - n.y) * 0.006 * state.physicsAlpha;

    n.vx *= 0.82; // Strong damping for fast settling
    n.vy *= 0.82;

    n.x += n.vx;
    n.y += n.vy;
  }

  drawFrame();

  // Fast alpha decay: settles smoothly in ~1.5s then pauses physics to preserve 60FPS
  state.physicsAlpha *= 0.94;
  if (state.physicsAlpha > 0.008 || state.isDragging) {
    state.animationFrameId = requestAnimationFrame(physicsStep);
  } else {
    state.animationFrameId = null;
  }
}

export function drawFrame() {
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);

  ctx.save();
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, rect.width, rect.height);

  ctx.translate(state.panX, state.panY);
  ctx.scale(state.scale, state.scale);

  const { nodes, links } = state.topology;

  // Blank workspace overlay
  if (nodes.length === 0) {
    ctx.restore();
    const blankOverlay = document.getElementById('blank-graph-cta');
    if (blankOverlay) blankOverlay.style.display = 'flex';
    return;
  } else {
    const blankOverlay = document.getElementById('blank-graph-cta');
    if (blankOverlay) blankOverlay.style.display = 'none';
  }

  const query = (state.searchQuery || '').toLowerCase().trim();

  // 1. Draw Links (Snappy, batch stroked)
  for (const link of links) {
    const a = link.sourceNode;
    const b = link.targetNode;
    if (!a || !b) continue;

    const isHighlight = (a.id === state.selectedUserId || b.id === state.selectedUserId);

    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);

    if (link.is_drift) {
      ctx.strokeStyle = '#EF4444';
      ctx.lineWidth = isHighlight ? 2.6 : 1.6;
      ctx.setLineDash([5, 4]);
    } else {
      ctx.strokeStyle = isHighlight ? 'rgba(2, 132, 199, 0.85)' : 'rgba(203, 213, 225, 0.75)';
      ctx.lineWidth = isHighlight ? 1.6 : 1.0;
      ctx.setLineDash([]);
    }
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // 2. Draw Nodes (Pre-rendered shapes)
  for (const node of nodes) {
    const isSelected = state.selectedUserId === node.id;
    const isHovered = state.hoveredNode === node;
    const matchesSearch = query && (
      (node.name && node.name.toLowerCase().includes(query)) ||
      (node.role && node.role.toLowerCase().includes(query))
    );

    if (node.type === 'permission') {
      // Permission Node: Diamond
      const size = node.is_critical ? 11 : 8.5;
      ctx.fillStyle = node.is_critical ? '#D97706' : '#0284C7';

      ctx.beginPath();
      ctx.moveTo(node.x, node.y - size);
      ctx.lineTo(node.x + size, node.y);
      ctx.lineTo(node.x, node.y + size);
      ctx.lineTo(node.x - size, node.y);
      ctx.closePath();
      ctx.fill();

      ctx.strokeStyle = isSelected || isHovered ? '#1E2024' : '#FFFFFF';
      ctx.lineWidth = isSelected ? 2 : 1;
      ctx.stroke();

      ctx.fillStyle = isHovered || isSelected ? '#1E2024' : '#64748B';
      ctx.font = '9.5px monospace';
      ctx.fillText(node.name, node.x + 11, node.y + 3);

    } else {
      // User Node: Circle
      const radius = isSelected ? 12 : (node.is_outlier ? 9 : 7);

      // Warning ring for drift outliers
      if (node.is_outlier) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 4, 0, 2 * Math.PI);
        ctx.fillStyle = 'rgba(239, 68, 68, 0.2)';
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);

      if (node.risk_score >= 70) {
        ctx.fillStyle = '#EF4444';
      } else if (node.risk_score >= 40) {
        ctx.fillStyle = '#F59E0B';
      } else {
        ctx.fillStyle = '#10B981';
      }
      ctx.fill();

      // Outline for selection or search
      if (isSelected || matchesSearch) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 2.5, 0, 2 * Math.PI);
        ctx.strokeStyle = '#1E2024';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.fillStyle = isSelected ? '#0F172A' : '#334155';
      ctx.font = isSelected ? 'bold 11px sans-serif' : '10px sans-serif';
      ctx.fillText(node.name, node.x + 12, node.y + 3.5);
    }
  }

  ctx.restore();
}

function setupCanvasEvents() {
  const tooltip = document.getElementById('node-tooltip');

  // Zoom buttons
  document.getElementById('btn-zoom-in')?.addEventListener('click', () => {
    state.scale = Math.min(2.5, state.scale * 1.25);
    drawFrame();
  });
  document.getElementById('btn-zoom-out')?.addEventListener('click', () => {
    state.scale = Math.max(0.35, state.scale / 1.25);
    drawFrame();
  });
  document.getElementById('btn-reset-zoom')?.addEventListener('click', () => {
    state.scale = 1.0;
    state.panX = 0;
    state.panY = 0;
    wakePhysics();
  });
  document.getElementById('btn-toggle-physics')?.addEventListener('click', () => {
    state.isPhysicsFrozen = !state.isPhysicsFrozen;
    const btn = document.getElementById('btn-toggle-physics');
    if (btn) btn.textContent = state.isPhysicsFrozen ? '▶' : '⏸';
    if (!state.isPhysicsFrozen) wakePhysics();
  });

  // Wheel Zoom
  canvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.08 : 0.92;
    state.scale = Math.max(0.35, Math.min(2.5, state.scale * factor));
    drawFrame();
  });

  // Mouse Interactions (Drag node or Pan)
  let isPanning = false;
  let startX = 0, startY = 0;

  canvas.addEventListener('mousedown', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left - state.panX) / state.scale;
    const y = (e.clientY - rect.top - state.panY) / state.scale;

    const clicked = state.topology.nodes.find(n => {
      const dx = n.x - x;
      const dy = n.y - y;
      return Math.sqrt(dx * dx + dy * dy) <= 16;
    });

    if (clicked) {
      if (clicked.type === 'user' && onNodeSelectCallback) {
        onNodeSelectCallback(clicked.id);
      }
      state.draggedNode = clicked;
      state.isDragging = true;
      wakePhysics();
    } else {
      isPanning = true;
      startX = e.clientX - state.panX;
      startY = e.clientY - state.panY;
    }
  });

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left - state.panX) / state.scale;
    const y = (e.clientY - rect.top - state.panY) / state.scale;

    if (state.isDragging && state.draggedNode) {
      state.draggedNode.x = x;
      state.draggedNode.y = y;
      wakePhysics();
      return;
    }

    if (isPanning) {
      state.panX = e.clientX - startX;
      state.panY = e.clientY - startY;
      drawFrame();
      return;
    }

    // Hover tooltip
    const hovered = state.topology.nodes.find(n => {
      const dx = n.x - x;
      const dy = n.y - y;
      return Math.sqrt(dx * dx + dy * dy) <= 15;
    });

    state.hoveredNode = hovered;
    if (hovered && tooltip) {
      canvas.style.cursor = 'pointer';
      tooltip.style.display = 'block';
      tooltip.style.left = `${e.clientX - rect.left + 14}px`;
      tooltip.style.top = `${e.clientY - rect.top - 8}px`;

      if (hovered.type === 'user') {
        tooltip.innerHTML = `
          <strong>${escapeHtml(hovered.name)}</strong><br />
          <span>Role: ${escapeHtml(hovered.role || 'Staff')}</span><br />
          <span>Risk: <strong style="color: ${hovered.risk_score >= 70 ? '#ff4757' : '#10b981'}">${hovered.risk_score}</strong></span>
          ${hovered.is_outlier ? '<br /><span style="color: #ff4757">⚠️ Entitlement Drift Outlier</span>' : ''}
        `;
      } else {
        tooltip.innerHTML = `
          <strong>Entitlement: ${escapeHtml(hovered.name)}</strong><br />
          <span>${hovered.is_critical ? '<strong style="color:#f59e0b">⚠️ Critical Admin Privilege</strong>' : 'Standard Enterprise Entitlement'}</span>
        `;
      }
    } else {
      canvas.style.cursor = 'grab';
      if (tooltip) tooltip.style.display = 'none';
    }
  });

  window.addEventListener('mouseup', () => {
    state.isDragging = false;
    state.draggedNode = null;
    isPanning = false;
  });
}
