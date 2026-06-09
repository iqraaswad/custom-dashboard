const axios = require('axios');
const https = require('https');

const BASE_URL = process.env.WAZUH_API_URL || 'https://localhost:55000';
const USER = process.env.WAZUH_USER || 'admin';
const PASSWORD = process.env.WAZUH_PASSWORD || 'admin';

const agent = new https.Agent({ rejectUnauthorized: false });

let token = null;

async function login() {
  try {
    const res = await axios.post(
      `${BASE_URL}/security/user/authenticate`,
      {},
      { httpsAgent: agent, auth: { username: USER, password: PASSWORD }, timeout: 10000 }
    );
    token = res.data.data.token;
    return token;
  } catch (err) {
    console.error('Wazuh login failed:', err.message);
    return null;
  }
}

async function api(method, endpoint, params = {}, body = null) {
  if (!token) await login();
  if (!token) throw new Error('Wazuh authentication failed');

  try {
    const opts = {
      method,
      url: `${BASE_URL}${endpoint}`,
      httpsAgent: agent,
      headers: { Authorization: `Bearer ${token}` },
      params,
      timeout: 15000
    };
    if (body) opts.data = body;

    const res = await axios(opts);
    return res.data;
  } catch (err) {
    if (err.response && err.response.status === 401) {
      token = null;
      await login();
      if (token) return api(method, endpoint, params, body);
    }
    throw err;
  }
}

async function getSummary() {
  try {
    const [agents, managers, agentsCount] = await Promise.all([
      api('get', '/agents', { limit: 1, offset: 0, select: 'status' }),
      api('get', '/cluster/nodes', {}).catch(() => ({ data: { affected_items: [] } })),
      api('get', '/agents', { limit: 1, offset: 0 })
    ]);

    const totalAgents = agentsCount?.data?.total_affected_items || 0;

    let active = 0, disconnected = 0, neverConnected = 0;
    if (agents?.data?.affected_items) {
      active = agents.data.affected_items.filter(a => a.status === 'active').length;
    }

    try {
      const allAgents = await api('get', '/agents', {
        limit: Math.min(totalAgents, 500), offset: 0, select: 'status'
      });
      if (allAgents?.data?.affected_items) {
        const items = allAgents.data.affected_items;
        active = items.filter(a => a.status === 'active').length;
        disconnected = items.filter(a => a.status === 'disconnected').length;
        neverConnected = items.filter(a => a.status === 'never_connected').length;
      }
    } catch (e) {}

    return {
      totalAgents,
      activeAgents: active,
      disconnectedAgents: disconnected,
      neverConnectedAgents: neverConnected,
      managerNodes: managers?.data?.total_affected_items || 0,
      connected: true
    };
  } catch (err) {
    console.error('Summary error:', err.message);
    return { totalAgents: 0, activeAgents: 0, disconnectedAgents: 0, neverConnectedAgents: 0, managerNodes: 0, connected: false, error: err.message };
  }
}

async function getAgents(limit = 50, offset = 0, search = '', status = '') {
  const params = { limit, offset, sort: '-dateAdd' };
  if (search) params.search = search;
  if (status && status !== 'all') params.status = status;

  const res = await api('get', '/agents', params);
  return {
    agents: res?.data?.affected_items || [],
    total: res?.data?.total_affected_items || 0
  };
}

const INDEXER_URL = process.env.WAZUH_INDEXER_URL || '';

function indexerHeaders() {
  const user = process.env.INDEXER_USER || 'admin';
  const pass = process.env.INDEXER_PASS || 'admin';
  const encoded = Buffer.from(`${user}:${pass}`).toString('base64');
  return {
    'Content-Type': 'application/json',
    'Authorization': `Basic ${encoded}`
  };
}

async function getAlerts(limit = 50, offset = 0, search = '', level = '') {
  if (!INDEXER_URL) return { alerts: [], total: 0, indexerRequired: true };
  try {
    const res = await axios.post(`${INDEXER_URL}/wazuh-alerts-*/_search`,
      { size: limit, from: offset, sort: [{ '@timestamp': 'desc' }] },
      { httpsAgent: agent, headers: indexerHeaders(), timeout: 15000 }
    );
    const hits = res?.data?.hits?.hits || [];
    const alerts = hits.map(h => h._source);
    const total = res?.data?.hits?.total?.value || 0;
    return { alerts, total, indexerRequired: false };
  } catch (err) {
    console.error('Alerts error:', err.message);
    return { alerts: [], total: 0, indexerRequired: true, error: err.message };
  }
}

async function getTopAlerts(days = 1) {
  if (!INDEXER_URL) return [];
  try {
    const res = await axios.post(`${INDEXER_URL}/wazuh-alerts-*/_search`,
      { size: 5, sort: [{ '@timestamp': 'desc' }] },
      { httpsAgent: agent, headers: indexerHeaders(), timeout: 15000 }
    );
    return (res?.data?.hits?.hits || []).map(h => h._source);
  } catch (err) {
    return [];
  }
}

async function getAgentDetail(agentId) {
  const res = await api('get', '/agents', { agents_list: agentId });
  return res?.data?.affected_items?.[0] || null;
}

async function getAgentsByGroup() {
  try {
    const res = await api('get', '/groups');
    const groups = res?.data?.affected_items || [];
    const result = [];
    for (const g of groups) {
      const countRes = await api('get', `/groups/${g.name}/agents`, { limit: 1 });
      result.push({ name: g.name, count: countRes?.data?.total_affected_items || 0 });
    }
    return result;
  } catch (err) {
    return [];
  }
}

async function getAlertLevelDistribution() {
  if (!INDEXER_URL) return [];
  try {
    const res = await axios.post(`${INDEXER_URL}/wazuh-alerts-*/_search`,
      { size: 0, aggs: { levels: { terms: { field: 'rule.level', size: 20 } } } },
      { httpsAgent: agent, headers: indexerHeaders(), timeout: 15000 }
    );
    const buckets = res?.data?.aggregations?.levels?.buckets || [];
    return buckets.map(b => ({ level: b.key, count: b.doc_count }));
  } catch (err) {
    return [];
  }
}

module.exports = { login, api, getSummary, getAgents, getAlerts, getTopAlerts, getAgentDetail, getAgentsByGroup, getAlertLevelDistribution };
