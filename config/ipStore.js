// config/ipStore.js
module.exports = {
  users: {},       // { uid: { ip, lastActive, blocked } }
  rateLimits: {},  // { ip: { count, lastRequest } }
  blockedIPs: {},  // { ip: blockUntil }
  blockedUsers: {} // { uid: blockUntil }
};