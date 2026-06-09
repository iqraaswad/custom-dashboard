const express = require('express');
const wazuh = require('../services/wazuh');

const router = express.Router();

function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  if (req.accepts('html')) return res.redirect(req.app.locals.basePath + '/login');
  return res.status(401).json({ error: 'Unauthorized' });
}

router.get('/', requireAuth, async (req, res) => {
  const summary = await wazuh.getSummary();
  const topAlerts = await wazuh.getTopAlerts();
  const groupData = await wazuh.getAgentsByGroup();
  const levelDist = await wazuh.getAlertLevelDistribution();

  res.render('dashboard', {
    title: 'Wazuh Dashboard',
    summary,
    topAlerts,
    groupData,
    levelDist,
    path: '/'
  });
});

router.get('/agents', requireAuth, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const search = req.query.search || '';
  const status = req.query.status || '';
  const offset = (page - 1) * limit;

  const { agents, total } = await wazuh.getAgents(limit, offset, search, status);
  const totalPages = Math.ceil(total / limit);

  res.render('agents', {
    title: 'Agents',
    agents,
    total,
    page,
    limit,
    totalPages,
    search,
    status,
    path: '/agents'
  });
});

router.get('/agents/:id', requireAuth, async (req, res) => {
  const agent = await wazuh.getAgentDetail(req.params.id);
  if (!agent) return res.status(404).render('error', { title: 'Not Found', message: 'Agent not found' });
  res.render('agent-detail', { title: `Agent: ${agent.name}`, agent, path: '/agents' });
});

router.get('/alerts', requireAuth, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const search = req.query.search || '';
  const level = req.query.level || '';
  const offset = (page - 1) * limit;

  const { alerts, total, indexerRequired } = await wazuh.getAlerts(limit, offset, search, level);
  const totalPages = Math.ceil(total / limit);

  res.render('alerts', {
    title: 'Alerts',
    alerts,
    total,
    page,
    limit,
    totalPages,
    search,
    level,
    indexerRequired,
    path: '/alerts'
  });
});

router.get('/overview', requireAuth, async (req, res) => {
  const summary = await wazuh.getSummary();
  const levelDist = await wazuh.getAlertLevelDistribution();
  const groupData = await wazuh.getAgentsByGroup();

  res.render('overview', {
    title: 'Overview',
    summary,
    levelDist,
    groupData,
    path: '/overview'
  });
});

router.get('/api/summary', requireAuth, async (req, res) => {
  const summary = await wazuh.getSummary();
  res.json(summary);
});

router.get('/api/agents', requireAuth, async (req, res) => {
  const { limit, offset, search, status } = req.query;
  const result = await wazuh.getAgents(
    parseInt(limit) || 50, parseInt(offset) || 0, search || '', status || ''
  );
  res.json(result);
});

router.get('/api/alerts', requireAuth, async (req, res) => {
  const { limit, offset, search, level } = req.query;
  const result = await wazuh.getAlerts(
    parseInt(limit) || 50, parseInt(offset) || 0, search || '', level || ''
  );
  res.json(result);
});

router.get('/api/overview', requireAuth, async (req, res) => {
  const [summary, levelDist, groupData] = await Promise.all([
    wazuh.getSummary(),
    wazuh.getAlertLevelDistribution(),
    wazuh.getAgentsByGroup()
  ]);
  res.json({ summary, levelDist, groupData });
});

module.exports = router;
