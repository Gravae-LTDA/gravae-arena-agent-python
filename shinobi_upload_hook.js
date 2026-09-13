// Shinobi customAutoLoad extension: final MP4 completion -> durable local uploader.
const fs = require('fs');
const http = require('http');
module.exports = function(s) {
    if (s.gravaeUploadCompletionHook) return;
    let config;
    try { config = JSON.parse(fs.readFileSync('/etc/gravae/shinobi-upload-hook.json', 'utf8')); }
    catch (_) { console.error('GRAVAE_UPLOAD_HOOK_CONFIG_UNAVAILABLE'); return; }
    if (!config.token || config.token.length < 32 || !config.groupKey) throw new Error('GRAVAE_UPLOAD_HOOK_CONFIG_INVALID');
    s.gravaeUploadCompletionHook = true;
    const pending = new Map();
    function send(key, item) {
        const body = JSON.stringify(item.payload);
        const request = http.request({host: '127.0.0.1', port: config.port || 8766, path: '/video-complete', method: 'POST',
            headers: {'Authorization': 'Bearer ' + config.token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}, timeout: 15000}, response => {
            response.resume();
            response.on('end', () => {
                if (response.statusCode === 202) pending.delete(key);
                else retry(key, item);
            });
        });
        request.on('timeout', () => request.destroy());
        request.on('error', () => retry(key, item));
        request.end(body);
    }
    function retry(key, item) {
        if (pending.get(key) !== item || item.timer) return;
        if (++item.attempts > 10) {
            pending.delete(key);
            console.error('GRAVAE_UPLOAD_HOOK_RECONCILIATION_REQUIRED');
            return;
        }
        item.timer = setTimeout(() => { item.timer = null; send(key, item); }, Math.min(30000, 1000 * 2 ** Math.min(item.attempts, 5)));
        item.timer.unref();
    }
    s.insertCompletedVideoExtender((monitor, video) => {
        if (monitor.ke !== config.groupKey) return;
        const filename = video.filename || video.file;
        const monitorId = monitor.mid || monitor.id;
        if (typeof filename !== 'string' || !filename.endsWith('.mp4')) return;
        const key = monitorId + '/' + filename;
        if (pending.has(key)) return;
        if (pending.size >= 1000) { console.error('GRAVAE_UPLOAD_HOOK_RECONCILIATION_REQUIRED'); return; }
        const item = {payload: {groupKey: monitor.ke, monitorId, filename}, attempts: 0, timer: null};
        pending.set(key, item);
        send(key, item);
    });
    console.log('GRAVAE_UPLOAD_COMPLETION_HOOK_READY');
};
