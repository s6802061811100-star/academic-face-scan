// Reusable Server-Side Google Apps Script API Service
// Handles communication between Node.js / Express and Google Apps Script Backend

const GAS_WEBAPP_URL = process.env.GAS_WEBAPP_URL || 'https://script.google.com/macros/s/AKfycbwkFTKnfM-DjUDg3uMjUl6JEyiCMk2fRofZzhJQlG19hDTXce4q9tQ-o_-rGjGBWu_h/exec';
const DEFAULT_TIMEOUT_MS = 15000;

/**
 * Call Google Apps Script Web App with robust error handling, timeout, and redirect support.
 * @param {string} action - Action name (e.g. 'ping', 'listSheets', 'getConfig', etc.)
 * @param {object} params - Query parameters or payload body
 * @param {string} method - 'GET' | 'POST'
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise<{success: boolean, data?: any, error?: string, raw?: any, status?: number}>}
 */
export async function callGasApi(action, params = {}, method = 'GET', timeoutMs = DEFAULT_TIMEOUT_MS, overrideUrl = '') {
  const resolvedUrl = (overrideUrl || GAS_WEBAPP_URL || '').trim();
  if (!/^https:\/\/script\.google\.com\/macros\/s\/[^/]+\/exec(?:$|\?)/.test(resolvedUrl)) {
    return {
      success: false,
      error: 'Google Apps Script Web App URL ไม่ถูกต้อง ต้องเป็น URL ที่ลงท้ายด้วย /exec',
      code: 'INVALID_GAS_URL'
    };
  }
  const targetUrl = new URL(resolvedUrl);

  let fetchOptions = {
    method: method.toUpperCase(),
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs)
  };

  if (fetchOptions.method === 'GET') {
    targetUrl.searchParams.set('action', action);
    Object.keys(params).forEach(k => {
      if (params[k] !== undefined && params[k] !== null) {
        targetUrl.searchParams.set(k, typeof params[k] === 'object' ? JSON.stringify(params[k]) : params[k]);
      }
    });
  } else {
    // POST request: Send JSON payload as text/plain;charset=utf-8 for Google Apps Script doPost compatibility
    const payload = { action, ...params };

    const safeLog = { ...payload };
    for (const key of [
      'descriptor',
      'face_descriptor',
      'faceDescriptor',
      'photo',
      'audio_base64',
      'audioBase64'
    ]) {
      if (key in safeLog) {
        safeLog[key] = `[REDACTED ${Array.isArray(safeLog[key]) ? safeLog[key].length + ' values' : 'data'}]`;
      }
    }

    console.log(`[GAS POST] Action: ${action}`, safeLog);
    fetchOptions.headers = {
      'Content-Type': 'text/plain;charset=utf-8'
    };
    fetchOptions.body = JSON.stringify(payload);
  }

  let response;
  try {
    response = await fetch(targetUrl.toString(), fetchOptions);
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      return {
        success: false,
        error: `Google Apps Script request timed out after ${timeoutMs / 1000}s`,
        code: 'TIMEOUT'
      };
    }
    return {
      success: false,
      error: `Network failure connecting to Google Apps Script: ${err.message}`,
      code: 'NETWORK_ERROR'
    };
  }

  console.log('Apps Script HTTP status:', response.status);

  // Read response as raw text first
  let rawText = '';
  try {
    rawText = await response.text();
  } catch (err) {
    return {
      success: false,
      error: `Failed to read response body: ${err.message}`,
      code: 'READ_ERROR'
    };
  }

  console.log('Apps Script response:', rawText.length > 800 ? rawText.slice(0, 800) + '…[truncated]' : rawText);

  let parsedData;
  try {
    parsedData = JSON.parse(rawText);
  } catch (err) {
    console.error('Apps Script raw response:', rawText);
    return {
      success: false,
      error: `Invalid JSON response from Google Apps Script: ${rawText.slice(0, 500)}`,
      raw: rawText,
      code: 'INVALID_JSON'
    };
  }

  return {
    success: true,
    data: parsedData
  };
}

export { GAS_WEBAPP_URL };
