/**
 * Central Reactive Application State
 */
export const state = {
  // Authentication & Session
  token: localStorage.getItem('accessdrift_token') || null,
  currentUser: null,
  isAuthenticated: false,
  isDemoWorkspace: false,

  // Governance & Roster
  branches: [],
  selectedBranch: 'all',
  users: [],
  topology: { nodes: [], links: [] },
  summary: {
    total_users: 0,
    outliers_detected: 0,
    high_risk_users: 0,
    clean_users: 0
  },
  availableRoles: [],
  availableBranches: [],

  // Active Inspections
  selectedUserId: null,
  remediationResult: null,
  policyTab: 'aws',
  activeView: 'graph', // 'graph' | 'table'
  searchQuery: '',
  tableFilterRole: 'all',
  tableFilterRisk: 'all',

  // Canvas Viewport & Physics
  scale: 1.0,
  panX: 0,
  panY: 0,
  isDragging: false,
  draggedNode: null,
  hoveredNode: null,
  physicsAlpha: 1.0,
  isPhysicsFrozen: false,
  animationFrameId: null,

  // Standard Entitlements Registry
  standardPermissions: [
    { id: "db:root", name: "db:root", critical: true },
    { id: "k8s:admin", name: "k8s:admin", critical: true },
    { id: "cloud:iam_admin", name: "cloud:iam_admin", critical: true },
    { id: "prod:deploy", name: "prod:deploy", critical: true },
    { id: "s3:backup_write", name: "s3:backup_write", critical: false },
    { id: "github:repo_write", name: "github:repo_write", critical: false },
    { id: "jira:admin", name: "jira:admin", critical: false },
    { id: "code:review", name: "code:review", critical: false },
    { id: "k8s:namespace_read", name: "k8s:namespace_read", critical: false },
    { id: "db:read", name: "db:read", critical: false },
    { id: "s3:read", name: "s3:read", critical: false },
    { id: "slack:admin", name: "slack:admin", critical: false },
    { id: "finance:gl_write", name: "finance:gl_write", critical: false },
    { id: "finance:reports_read", name: "finance:reports_read", critical: false },
    { id: "stripe:billing_admin", name: "stripe:billing_admin", critical: true },
    { id: "hr:payroll_write", name: "hr:payroll_write", critical: true },
    { id: "hr:employee_pii_read", name: "hr:employee_pii_read", critical: false },
    { id: "hr:onboarding_admin", name: "hr:onboarding_admin", critical: false }
  ]
};
